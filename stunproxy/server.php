<?php

/*
	STUN Rendez-vous server
	(part of stunproxy)

	The Stun tool that actually allows two stun-able clients to discover
	and connect each other.

	Written by [exa] 2009, license is GPLv3, so please behave.

	FUNCTION:
	pre] both clients create a shared key that connects them
	a] both clients get stun discovery on their mapped addresses
	b] both clients sumbit their mapped addresses and ports to the server
	c] server tells them what the other peer's mapped address is,
		or tells them to retry (with http 202 accepted)
	
	a and b repeats on failure.
	
	PROTOCOL:
	Addresses are in textual form of transport address, in:

		ipv4:port
	
	(please note that ipv6 doesnt need stunning.)

	keys are sequences of characters that match [0-9a-zA-Z\+\/]+ , like:
		
		vukSxf+mwWXqhrydB5yhlmtOdY+zQ2V5fZDRX/a1kRQ

	minimal requested key length is 16 characters, to avoid frequent
	unwanted collisions. Maximal is 512, which gives us 3072-bit keys.

	Request is written in GET:

	?a=<address>&k=<key>

	so, for example:

	GET stun.php?a=77.1.4.123:23&k=5yhlmtOdY+zQ2V5fZDRX/x

	Response can be both:

	RETR <newline>
	
	which tells the client that his request is being processed and he
	should retry any time soon

	or:

	PEER <newline>
	<peer-mapped-address>  <newline>

	or:

	FAIL <newline>

	says that you fucked something up.


	Please take note about standartized HTTP response times, so common
	retry times should be at least 10 seconds, so server doesn't die of it.
	Faster retry is not needed, as server guarantees that the requests get
	cached at least for those 10 seconds before forgotten.
	Retry time can be shortened, if given implementation is so realtime that
	it needs it.

	SECURITY

	none by default.
	You should use https if you don't want to use your keys more times than
	once.
	If not, you can be misdirected to another peer easily, and you
	definately should use some transport authentication.
*/

$db='db.txt';
$maxentries=1024;
$maxkey=512;
$minkey=16;
$maxage=20; //seconds
header('Content-type: text/plain');

$timenow=time();

function error($e)
{
	echo "FAIL\r\nYour request is not acceptable. Error was: ".$e;
	exit(0);
}

$responded=FALSE;

function response($ip)
{
	global $responded;
	global $responsemime;

	if($responded) return;
	$responded=TRUE;

	echo "PEER\r\n".$ip."\r\n";
}

function accepted()
{
	global $responded;
	if($responded) return;

	echo "RETR\r\nYour request is accepted. Please retry soon.";
}


if(!isset($_GET['a'])) error('no address');
if(!isset($_GET['k'])) error('no key');

$req_addr=$_GET['a'];
$req_key=$_GET['k'];

if(strlen($req_key)<16) error('key short');
if(strlen($req_key)>512) error('key long');

if(!preg_match('/\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}:\d{1,5}/',$req_addr)) error('doesnt match ip4:port');
if(!preg_match('/[a-zA-Z0-9\+\/]*/',$req_key)) error('illegal key');


$data=array();

function load_db()
{
	global $data;
	global $db;
	$s=@file_get_contents($db);
	if(!$s)return;
	foreach(explode("\n",$s) as $i)
		if(strlen(trim($i))>0)
			$data[]=explode("\t",$i);
}

function save_db()
{
	global $data;
	global $db;
	$x=array();
	foreach($data as $d) $x[]=implode("\t",$d);
	file_put_contents($db,implode("\n",$x));
}

function age_filter($x)
{
	global $maxage;
	global $timenow;

	return (intval($x[0])+ $maxage > $timenow);
}

function drop_old()
{
	global $data;
	global $maxentries;

	$data=array_filter($data,age_filter);

	while(count($data)>$maxentries) array_shift($data);
}

load_db();
drop_old();

$present=FALSE;

foreach($data as $k => $d) {
	if($d[2]==$req_key) {
		if($d[1]==$req_addr){
			$data[$k][0]="$timenow";
			$present=TRUE;
		}
		else response($d[1]);
	}
}

if(!$present){
	$data[]=array("$timenow",$req_addr,$req_key);
}

accepted();

save_db();

?>
