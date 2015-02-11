<?php

/*
   JSON encode the GIT log
   by Jeremy Newman <jnewman@codeweavers.com>
*/

// number of items to show
$show = 200;

// local path to git repository
$repo = '/home/winehq/opt/source/git/wine.git';

// return log
$log = array();

// only continue if dir exists
if (is_dir($repo))
{
    // fetch git history log of HEAD
    $log_lines = shell_exec("git --git-dir {$repo} --no-pager log --max-count={$show} --format=\"%ct, %H, \\\"%an\\\", %s\"");

    $log_lines = preg_split("/\n/", trim($log_lines));
    foreach ($log_lines as $line)
    {
        $s = preg_split("/,\s+/", $line, 4);
        $s[2] = str_replace('"', "", $s[2]);
        $log[] = $s;
    }
}

// json encode and return
header("Content-type: application/x-javascript; charset=UTF-8");
echo json_encode($log);

?>
