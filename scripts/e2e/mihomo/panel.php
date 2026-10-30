<?php
// CLI-only fixtures and observations for a disposable full-stack deployment.
if (PHP_SAPI !== 'cli' || getenv('V2BX_E2E_ISOLATED') !== '1') exit(64);
require '/app/vendor/autoload.php';
$app = require '/app/bootstrap/app.php';
$app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
if (config('database.default') !== 'mysql' || config('database.connections.mysql.database') !== 'irboard_e2e') exit(65);

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Redis;
use App\Models\User;
use App\Models\Plan;
use App\Protocols\Mihomo\ProtocolRegistry as Registry;
use Tests\Fixtures\MihomoProfiles;

$action = $argv[1] ?? 'snapshot';
if ($action === 'seed') {
    $now = time();
    $protocols = array_values(array_unique(array_merge(['http','socks5','mieru','shadowquic','sudoku','snell','vmess','vless','trojan','tuic','hysteria2','anytls','trusttunnel','shadowsocks','hysteria','mdns'], Registry::types())));
    $admin = User::create(['email'=>'admin@e2e.invalid','password'=>password_hash('isolated-e2e-password', PASSWORD_BCRYPT),'uuid'=>'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee','token'=>'e2e-admin-only','is_admin'=>1,'is_staff'=>0,'created_at'=>$now,'updated_at'=>$now]);
    $out = [];
    foreach ($protocols as $index => $type) {
        $group = 100 + $index;
        DB::table('v2_server_group')->insert(['id'=>$group,'name'=>'e2e ' . $type,'created_at'=>$now,'updated_at'=>$now]);
        $plan = Plan::create(['group_id'=>$group,'transfer_enable'=>100,'name'=>'e2e ' . $type,'show'=>1,'renew'=>1,'month_price'=>100,'created_at'=>$now,'updated_at'=>$now]);
        $uid = 1000 + $index;
        $user = User::create(['id'=>$uid,'email'=>$type.'@e2e.invalid','password'=>password_hash('isolated-e2e-password', PASSWORD_BCRYPT),'uuid'=>sprintf('11111111-2222-4333-8444-%012d',$uid),'token'=>'e2e-sub-'.$type,'is_admin'=>0,'is_staff'=>0,'banned'=>0,'plan_id'=>$plan->id,'group_id'=>$group,'transfer_enable'=>100*1073741824,'u'=>0,'d'=>0,'expired_at'=>$now+86400,'speed_limit'=>0,'device_limit'=>2,'created_at'=>$now,'updated_at'=>$now]);
        $payload = Registry::has($type) ? Registry::storage($type, MihomoProfiles::settings($type)) : [];
        $payload = array_replace($payload, ['name'=>'e2e-'.$type,'host'=>'node.e2e.test','port'=>24000+$index,'server_port'=>24000+$index,'show'=>1,'sort'=>0,'rate'=>1,'group_id'=>[(string)$group],'route_id'=>[],'tags'=>['e2e'],'parent_id'=>null]);
        if (in_array($type, ['http','socks5','mieru','shadowquic'])) {
            $payload['managed']=true; $payload['username']=''; $payload['password']='';
        }
        if ($type === 'http' || $type === 'socks5') { $payload['tls']=true; $payload['skip_cert_verify']=false; }
        if ($type === 'http') $payload['sni']='node.e2e.test';
        if ($type === 'mieru') { $payload['transport']='TCP'; $payload['udp']=true; $payload['port_range']=null; }
        if ($type === 'shadowquic') $payload['sni']='node.e2e.test';
        // The panel generates the Sudoku master key and hands each user a split.
        if ($type === 'sudoku') { $payload['managed']=true; $payload['key']=''; }
        // Each user's PSK is also their ShadowTLS v3 password.
        if ($type === 'snell') { $payload['managed']=true; $payload['psk']=''; $payload['version']=4; $payload['udp']=true; $payload['obfs_opts']=['mode'=>'shadow-tls','version'=>3,'host'=>'node.e2e.test']; }
        if ($type === 'vmess') $payload += ['network'=>'tcp','tls'=>1,'tlsSettings'=>['serverName'=>'node.e2e.test','allowInsecure'=>false]];
        if ($type === 'vless') $payload += ['network'=>'tcp','tls'=>1,'tls_settings'=>['server_name'=>'node.e2e.test'],'flow'=>null];
        if ($type === 'trojan') $payload += ['network'=>'tcp','server_name'=>'node.e2e.test','allow_insecure'=>0];
        if ($type === 'tuic') $payload += ['server_name'=>'node.e2e.test','insecure'=>0,'disable_sni'=>0,'zero_rtt_handshake'=>0,'congestion_control'=>'cubic','udp_relay_mode'=>'native'];
        if ($type === 'anytls') $payload += ['tls'=>1,'server_name'=>'node.e2e.test','insecure'=>0,'padding_scheme'=>'[]'];
        if ($type === 'trusttunnel') $payload += ['hostname'=>'node.e2e.test','custom_sni'=>'node.e2e.test','cert_type'=>'provided','cert_chain_path'=>'/certs/node.pem','cert_key_path'=>'/certs/node.key','upstream_protocol'=>'http2'];
        if ($type === 'hysteria2' || $type === 'hysteria') $payload += ['version'=>$type==='hysteria2'?2:1,'server_name'=>'node.e2e.test','insecure'=>0,'up_mbps'=>100,'down_mbps'=>100];
        if ($type === 'shadowsocks') $payload += ['cipher'=>'aes-128-gcm'];
        if ($type === 'mdns') $payload += ['domain'=>['e2e.invalid'],'encryption_method'=>0,'encryption_key'=>null];
        $out[$type] = ['user'=>$user->only(['id','email','uuid','token','group_id','plan_id']),'payload'=>$payload];
    }
    Cache::put('exchange_rate',['rate'=>60000,'time'=>$now,'date'=>date('Y-m-d H:i:s')],3600);
    echo json_encode($out, JSON_UNESCAPED_SLASHES|JSON_PRETTY_PRINT), "\n";
} elseif ($action === 'snapshot') {
    $users = [];
    foreach (User::where('is_admin',0)->get() as $u) $users[$u->id] = ['u'=>(int)$u->u,'d'=>(int)$u->d,'banned'=>(int)$u->banned,'speed_limit'=>(int)$u->speed_limit,'uuid'=>$u->uuid,'token'=>$u->token,'alive'=>Cache::get('ALIVE_IP_USER_'.$u->id)];
    echo json_encode(['users'=>$users,'pending_up'=>Redis::hGetAll('v2board_upload_traffic'),'pending_down'=>Redis::hGetAll('v2board_download_traffic'),'failed_jobs'=>DB::table('failed_jobs')->count()], JSON_UNESCAPED_SLASHES), "\n";
} elseif ($action === 'templates') {
    $result=[]; foreach (Registry::types() as $type) $result[$type]=Registry::storage($type,MihomoProfiles::settings($type));
    echo json_encode($result,JSON_UNESCAPED_SLASHES), "\n";
} else exit(66);
