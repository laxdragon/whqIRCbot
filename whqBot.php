<?php
/*
 * =====================================================================================================================
 * WineHQ IRC Bot
 *  by Jeremy Newman <jnewman@codeweavers.com>
 * =====================================================================================================================
 */

// exit out if attempting to run as web script
if (!empty($_SERVER['HTTP_HOST']))
    die("This is NOT a web script!");

// the path where this script is located
$path = realpath(dirname(__FILE__));

// bot Config
$config = array(
                // general
                'server'    => 'irc.freenode.net',
                'port'      => 6667,
                'ssl'       => false,
                'name'      => 'WineHQ Bot',
                'nick'      => 'whqBot',
                'pass'      => '',
                'channel'   => '#winehackers',

                // admin user
                'admin'     => array('laxdragon'),

                // enable log
                'logging'   => false,
                'log_path'  => "{$path}/log/",

                // insult DB
                'insults'   => "{$path}/data/insult.txt"
               );

// GIT JSON feeds config
$gitJSON = array(
                 0 => array(
                            'code' => 'wine',
                            'url'  => 'http://wine.codeweavers.com/gitJSON.php',
                            'date' => 0
                           )
                );

// load modules and defines
require_once("{$path}/lib/ircBot.php");

//Start the bot
$bot = new ircBot($config);
$bot->addTimer("whqGITlog", 300, "whqGITlog");
$bot->addParser('/[a-f0-9]{8,}/i', "whqGITcommit");
//$bot->addParser('/bug ([0-9]+)/i', "WHQgetBug");
$bot->start();

// GIT log JSON parser
// requires gitJSON script be setup on server with repository
function whqGITlog (&$irc)
{
    // import RSS feed config
    global $gitJSON;

    // loop through RSS feeds
    foreach ($gitJSON as &$FEED)
    {
        // parse XML from feed
        echo "-- whqGITlog: reading GIT JSON feed: [{$FEED['code']}] ({$FEED['date']}) {$FEED['url']}\n";
        if ($json = json_decode(file_get_contents($FEED['url'])))
        {
            $newfirst = 0;
            foreach ($json as $c => $list)
            {
                list($date, $sha, $author, $comment) = $list;
                if (empty($date))
                    break;
                if ($c == 0)
                    $newfirst = $date;
                if ($FEED['date'] > 0 and $date > $FEED['date'])
                {
                    $sha = substr(preg_replace('/^.*\/([0-9a-z]+)$/', '$1', $sha), 0, 9);
                    $irc->say($irc->config['channel'],
                              $irc->color('grey',"[{$FEED['code']}]")." ".
                              $irc->color('cyan',$author)." * ".
                              $irc->color('red',$sha)." : ".
                              $irc->color('lime',$comment));
                }
            }
            $FEED['date'] = $newfirst;
        }
    }
}

// Output a nicely formatted GIT url for any git ID
function whqGITcommit (&$irc, $id = array())
{
    if (empty($id[0]))
        return "";
    $gitURL  = "http://source.winehq.org/git/";
    $repos = array("wine.git");
    $r = array();
    foreach ($repos as $repo)
    {
        $ch = curl_init("{$gitURL}{$repo}/patch/{$id[0]}");
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
        $w = curl_exec($ch);
        $s = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if (empty($w) or $s == 404)
            continue;
        preg_match('/From ([a-fA-F0-9]{8,}) .*\nFrom: (.*)\nDate: (.*)\nSubject: (.*)\n/', $w, $r);
        array_push($r, $repo);
        unset($w, $ch);
        break;
    }
    if (empty($r))
        return "";
    $r = array_map(function($x){return iconv_mime_decode($x,0,"UTF-8");},$r);
    return $irc->color('cyan',$r[2]).": ".$irc->color('bold',$r[4])." ".$irc->color('grey',"{$gitURL}{$r[5]}/commit/{$r[1]}");
}

// output a nicely formatted URL for WineHQ Bugs
function WHQgetBug (&$irc, $id = array())
{
    if (empty($id[0]) or empty($id[1]))
        return "";
    $bug = $id[1];
    $b = json_decode(file_get_contents("https://www.winehq.org/~wineowner/bug_json.php?bug_id={$bug}"));
    if (empty($b) or empty($b->bug_id))
        return "";
    $url = 'http://bugs.winehq.org/show_bug.cgi?id=';
    $r = (!empty($b->resolution) ? " {$b->resolution}" : "");
    $status = array('UNCONFIRMED'=>'teal','NEW'=>'green','ASSIGNED'=>'lime','CLOSED'=>'red','RESOLVED'=>'orange','REOPENED'=>'purple');
    return "winehq bug:[".$irc->color('cyan',$b->bug_id)."] ".$irc->color('bold',$b->short_desc)." - ".
           $irc->color("{$status[$b->bug_status]}","{$b->bug_status}{$r}")." - ".$irc->color('grey',"{$url}{$bug}");
}

// done
?>
