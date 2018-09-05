<?php
/*
 * =========================================================================================================
 * ircBot Class
 *  by Jeremy Newman <jnewman@codeweavers.com>
 *  https://github.com/laxdragon/whqIRCbot
 * =========================================================================================================
 */
class ircBot
{
    // global config
    public $config = array();

    // current channels
    public $channels = array();

    // server connection socket
    private $socket = null;

    // insult database
    private $insults = array();

    // timestamp of start
    private $starttime = null;

    // seen database
    private $seen = array();

    // page database
    private $pages = array();

    // parsers
    private $parsers = array();

    // timer functions
    private $timers = array();

    // message queue
    private $queue = array();

    // ircBot Version
    private $version = '3.5';

    /*
     * =====================================================================================================
     * Open server connection and login the bot
     * =====================================================================================================
     */
    function __construct ($config)
    {
        // copy config
        $this->config = $config;
    }

    /*
     * =====================================================================================================
     * Close Server Connection
     * =====================================================================================================
     */
    function __destruct ()
    {
        foreach ($this->channels as $chan => $data)
        {
            $this->log($chan, "<hr><b>Ended: ".date('Y-m-d h:i:s')."</b>");
            $this->say($chan, "{$this->config['nick']} Shutting Down!");
        }
        $this->sendData('QUIT', 'cwBot');
        echo "... ircBot Shutting Down!\n";
        if (!empty($this->socket))
            fclose($this->socket);
    }

    /*
     * =====================================================================================================
     * Start the IRC Connection
     * =====================================================================================================
     */
    public function start ()
    {
        // return if we are already connected
        if ($this->socket)
            return;

        // no time limit to this PHP process
        set_time_limit(0);

        // set the ticks for signal processing
        declare(ticks = 1);

        // define our signal handling function
        pcntl_signal(SIGTERM, array(&$this, "SIG_handler"));
        pcntl_signal(SIGHUP,  array(&$this, "SIG_handler"));

        // starttime of bot
        $this->starttime = time();

        // open socket to IRC server
        $this->connect();

        // load insult DB
        if (file_exists($this->config['insults']))
        {
            $fd = @fopen($this->config['insults'], "r");
            while (!feof ($fd))
            {
                $this->insults[] = trim(fgets($fd, 4096));
            }
            fclose($fd);
            if (count($this->insults))
                echo " -- insult db: loaded (".count($this->insults).") insults\n";
        }

        // login
        $this->login();

        // start main loop
        $this->main();
    }

    /*
     * =====================================================================================================
     * Main Server Connection Loop
     * =====================================================================================================
     */
    private function main ()
    {
        // inital timer
        $timer = microtime(true);

        // loopy
        while (true)
        {
            // sleep 100ms to prevent high CPU usage
            usleep(100000);

            // check connection status
            if (!empty($this->socket))
                $meta = stream_get_meta_data($this->socket);
            if (empty($this->socket) or empty($meta) or !empty($meta['eof']))
            {
                // lost connection, reconnect
                echo "-- LOST CONNECTION... reconnecting...\n";
                $this->disconnect();
                $this->connect();
                $this->login();
                continue;
            }
            unset($meta);

            // run user defined timers
            $this->runTimers();

            // send message in the queue every half second max
            if ((microtime(true) - $timer) >= 0.5)
            {
                if (count($this->queue))
                    $this->sendData(array_shift($this->queue));
                $timer = microtime(true);
            }

            // get data from server
            $msg = $this->getData();

            // continue if there was no command
            if (empty($msg[0]))
                continue;

            // ping-pong with the server to stay connected
            if ($msg[0] == 'PING')
            {
                // reply
                $this->sendData('PONG', $msg[0]);
                continue;
            }

            // continue if there was no further data
            if (empty($msg[1]))
                continue;

            // names list
            if ($msg[1] == '353')
            {
                for ($i = 6; $i < (count($msg)+1); $i++)
                {
                    if (!empty($msg[$i]))
                        $this->onJoin($msg[4], trim(preg_replace('/^(\@|\:)/', '', $msg[$i])));
                }
                continue;
            }

            // topic change
            if ($msg[1] == '332')
            {
                $this->channels[$msg[3]]['topic'] = $this->unsep($this->getMsg($msg, 4));
            }

            // when someone joins the channel
            if ($msg[1] == 'JOIN')
            {
                $this->onJoin($this->unsep($msg[2]), $this->getNick($msg[0]));
                continue;
            }

            // when someone is kicked off the channel
            if ($msg[1] == 'KICK')
            {
                if ($this->unsep($msg[4]) == $this->config['nick'])
                {
                    // hey, someone kicked the bot, that will not do!
                    $this->joinChannel($msg[2]);
                    $this->say($msg[2], $this->color('red', $this->getNick($msg[0])).
                               ", Trying to kick me eh? That will not do! Please OP me so I can do my work.");
                }
                else
                {
                    // track the kicked user
                    $this->onPart($this->unsep($msg[2]), $this->unsep($msg[3]));
                }
                continue;
            }

            // when someone leaves the channel
            if ($msg[1] == 'PART')
            {
                $this->onPart($msg[2], $this->getNick($msg[0]));
                continue;
            }

            // when someone leaves the channel
            if ($msg[1] == 'QUIT')
            {
                if ($this->getNick($msg[0]) == $this->config['nick'])
                {
                    // we lost connection attempt to reconnect
                    $this->disconnect();
                    $this->connect();
                    $this->login();
                }
                else
                {
                    // track the users quit
                    $this->onPart('ALL', $this->getNick($msg[0]));
                }
                continue;
            }

            // when someone changes their nick
            if ($msg[1] == 'NICK')
            {
                $this->onNick($this->getNick($msg[0]), $this->unsep($msg[2]));
                continue;
            }

            // log the chat
            if ($msg[1] == 'PRIVMSG')
            {
                $this->updateSeen($this->unsep($msg[2]), $this->getNick($msg[0]));
                $this->onPrivMsg($msg);
            }
        }
        // end main loop
    }

    /*
     * =====================================================================================================
     * Connect to the IRC Server
     * =====================================================================================================
     */
    private function connect ()
    {
        // error out on no config
        if (empty($this->config['server']) or empty($this->config['port']))
        {
            echo "Error: no config!\n";
            exit();
        }

        // connect
        echo "Connecting to: irc://{$this->config['server']}:{$this->config['port']}\n";

        // set stream options
        $options = array();
        if (!empty($this->config['ssl']))
        {
            $options['ssl']['verify_peer'] = false;
            $options['ssl']['verify_peer_name'] = false;
        }

        // verify connection, loop until connected
        $c = 0;
        while (empty($this->socket))
        {
            // open socket
            $this->socket = @stream_socket_client($this->config['server'].':'.$this->config['port'], $errno, $errstr, 15, STREAM_CLIENT_CONNECT, stream_context_create($options));

            // error out if no initial connection
            if (empty($this->socket))
            {
                // on 5 failures, just give up
                echo "ERROR:[{$errno}] {$errstr}\n";
                if ($c == 5)
                {
                    echo "Error! Unable to connect!\n";
                    exit();
                }
                sleep(5);
            }

            // count connection attempts
            $c++;
        }

        // enable TLS
        if (!empty($this->config['ssl']))
        {
            echo "enabling SSL!\n";
            stream_socket_enable_crypto($this->socket, true, STREAM_CRYPTO_METHOD_ANY_CLIENT);
        }

        // set socket stream to non blocking
        stream_set_blocking($this->socket, false);
    }

    /*
     * =====================================================================================================
     * Disconnect from the IRC Server
     * =====================================================================================================
     */
    private function disconnect ()
    {
        echo "Disconnecting from irc://{$this->config['server']}:{$this->config['port']}\n";
        if (!empty($this->socket))
            fclose($this->socket);
        $this->socket = null;
        $this->channels = array();
        sleep(5);
    }

    /*
     * =====================================================================================================
     * Logs the bot in on the server
     * =====================================================================================================
     */
    private function login ()
    {
        // init sasl login
        if (!empty($this->config['sasl']))
        {
            echo "enabling SASL!\n";
            $this->sendData('CAP', 'REQ :sasl');
        }

        // send user info
        $this->sendData('NICK', $this->config['nick']);
        $this->sendData('USER', $this->config['nick'].' 0 0 :'.$this->config['name']);
        if (!empty($this->config['pass']))
            $this->sendData('PASS', $this->config['pass']);

        // login loop
        while (true)
        {
            // sleep 100ms to prevent high CPU usage
            usleep(100000);

            // get data from server
            $msg = $this->getData();

            // continue if there was no command
            if (empty($msg[0]))
                continue;

            // SASL password (null byte seperated base64 encoded)
            if ($msg[0] == 'AUTHENTICATE' and $msg[1] == '+')
            {
                $spass = $this->config['nick']."\x00".$this->config['nick']."\x00".$this->config['sasl'];
                $this->sendData('AUTHENTICATE', base64_encode($spass));
                unset($spass);
                continue;
            }

            // login message handler
            switch ($msg[1])
            {
                // SASL set authenticate mode
                case 'CAP':
                    if ($msg[3] == 'ACK')
                        $this->sendData('AUTHENTICATE', 'PLAIN');
                    break;

                // SASL successful
                case '903':
                    $this->sendData('CAP', 'END');
                    break;

                // SASL login failed!
                case '904':
                    echo "SASL login failed!\n";
                    exit();

                // login complete, break out of login loop during MOTD
                case '001':
                    break 2;
            }
        }

        // register with nickServ
        if (!empty($this->config['nickserv']))
        {
            sleep(1);
            $this->sendData('PRIVMSG', "nickserv :identify {$this->config['nick']} {$this->config['nickserv']}");
        }

        // join channels
        foreach ($this->config['channels'] as $chan)
        {
            sleep(2);
            $this->joinChannel($chan);
        }
    }

    /*
     * =====================================================================================================
     * Join a Channel
     * =====================================================================================================
     */
    private function joinChannel ($channel)
    {
        // start log
        $this->log($channel, "<b>Started {$channel}: ".date('Y-m-d h:i:s')."</b><hr>");

        // join
        $this->sendData('JOIN', $channel);
        $this->channels[$channel] = array('join' => time(), 'topic' => '');
    }

    /*
     * =====================================================================================================
     * remove separator from string
     * =====================================================================================================
     */
    private function unsep ($str)
    {
        return ltrim($str, ":");
    }

    /*
     * =====================================================================================================
     * get the nick from a string
     * =====================================================================================================
     */
    private function getNick ($str)
    {
        return preg_replace('/^\:(.+)\!.*$/', '$1', $str);
    }

    /*
     * =====================================================================================================
     * pretty up a log line
     * =====================================================================================================
     */
    private function filter_log ($type, $chan, $nick, $msg)
    {
        $nick = $this->getNick($nick);
        $msg = $this->unsep($msg);
        if ($type == "PRIVMSG")
        {
            return date("[H:i]")." &lt;{$nick}&gt; {$msg}";
        }
        return null;
    }

    /*
     * =====================================================================================================
     * get just the message from the line, using a start point
     * =====================================================================================================
     */
    private function getMsg ($msg = array(), $start = 3)
    {
        if (!$start)
            $start = 3;
        $message = "";
        for ($i = $start; $i <= (count($msg)); $i++)
        {
            if (isset($msg[$i]))
                $message .= ($message ? " " : "").$msg[$i];
        }
        return $message;
    }

    /*
     * =====================================================================================================
     * Send command to IRC server
     * =====================================================================================================
     */
    private function sendData ($cmd, $msg = null)
    {
        $cmd = trim($cmd);
        $msg = trim($msg);
        if ($this->socket)
        {
            if ($msg == null)
            {
                fputs($this->socket, "{$cmd}\r\n");
                echo "{$cmd}\n";
            }
            else
            {
                fputs($this->socket, "{$cmd} {$msg}\r\n");
                echo "{$cmd} {$msg}\n";
            }
            flush();
        }
    }

    /*
     * =====================================================================================================
     * get messages from server
     * =====================================================================================================
     */
    private function getData ()
    {
        // get message data from server
        $data = fgets($this->socket, 256);
        $msg = explode(' ', trim($data));
        flush();

        // continue if there was no command
        if (empty($msg[0]))
            return array();

        // output data from server to console
        echo "{$data}";
        //print_r($msg); // debug

        // return data
        return $msg;
    }

    /*
     * =====================================================================================================
     * Say Somthing
     * =====================================================================================================
     */
    public function say ($channel, $say)
    {
        array_push($this->queue, "PRIVMSG {$channel} :{$say}");
    }

    /*
     * =====================================================================================================
     * Change User Mode flag
     * =====================================================================================================
     */
    private function changeMode ($channel = '', $user = '', $mode = '', $set = true)
    {
        $onoff = ($set ? "+" : '-');
        $this->sendData('MODE', "{$channel} {$onoff}{$mode} {$user}");
    }

    /*
     * =====================================================================================================
     * Send a Random Insult to User
     * =====================================================================================================
     */
    private function insult ($channel = '', $user = '')
    {
        $rand = rand(0, (count($this->insults) - 1));
        $line = $this->insults[$rand];
        $line = preg_replace('/\$nick/', trim($user), $line);
        $this->say($channel, trim($line));
    }

    /*
     * =====================================================================================================
     * Is this user an Admin
     * =====================================================================================================
     */
    private function isAdmin ($user)
    {
        if (in_array($user, $this->config['admin']))
            return true;
        return false;
    }

    /*
     * =====================================================================================================
     * Is this user currently online
     * =====================================================================================================
     */
    private function isOnline ($channel, $nick)
    {
        if (isset($this->seen[$nick][$channel]))
        {
            if ($this->seen[$nick][$channel]['part'] == 0)
                return true;
        }
        return false;
    }

    /*
     * =====================================================================================================
     * Is this user currently online
     * =====================================================================================================
     */
    private function lastOnline ($channel, $nick)
    {
        if (isset($this->seen[$nick][$channel]['part']) and $this->seen[$nick][$channel]['part'] > 0)
        {
            return $this->seen[$nick][$channel]['part'];
        }
        return 0;
    }

    /*
     * =====================================================================================================
     * onJoin handler
     * =====================================================================================================
     */
    private function onJoin ($channel, $nick)
    {
        if ($nick)
        {
            // update seen db
            if (empty($this->seen[$nick][$channel]['join']))
                $this->seen[$nick][$channel]['join'] = time();
            $this->seen[$nick][$channel]['last'] = time();
            $this->seen[$nick][$channel]['part'] = 0;
            // check for admin
            if ($this->isAdmin($nick))
            {
                // set OP flag
                $this->changeMode($channel, $nick, "o", true);
            }
            // check for pages
            if (isset($this->pages[$nick]) and count($this->pages[$nick]))
            {
                foreach ($this->pages[$nick] as $page)
                {
                    $d = date('Y-m-d H:i', $page['time']);
                    $this->say($channel, "$nick! On {$d}, {$page['from']} wanted to tell you in {$page['chan']} ".
                                         "the following: {$page['page']}");
                    unset($d);
                }
                unset($this->pages[$nick]);
            }
        }
    }

    /*
     * =====================================================================================================
     * onPart handler
     * =====================================================================================================
     */
    private function onPart ($channel, $nick)
    {
        if ($channel == 'ALL')
        {
            if (empty($this->seen[$nick]))
                return;
            foreach ($this->seen[$nick] as $in_channel => $data)
            {
                $this->seen[$nick][$in_channel]['part'] = time();
            }
        }
        else
        {
            $this->seen[$nick][$channel]['part'] = time();
        }
    }

    /*
     * =====================================================================================================
     * onNick handler
     * =====================================================================================================
     */
    private function onNick ($oldnick, $newnick)
    {
        // update the seen with the new nick
        if (isset($this->seen[$oldnick]))
        {
            $this->seen[$newnick] = $this->seen[$oldnick];
            unset($this->seen[$oldnick]);
        }
        $this->onJoin($this->config['channel'], $newnick);
    }

    /*
     * =====================================================================================================
     * Update Seen
     * =====================================================================================================
     */
    private function updateSeen ($channel, $nick)
    {
        $this->seen[$nick][$channel]['last'] = time();
    }

    /*
     * =====================================================================================================
     * Set Topic
     * =====================================================================================================
     */
    public function setTopic ($channel, $topic)
    {
        if ($channel and $topic)
        {
            $this->sendData("TOPIC {$channel} :{$topic}");
            $this->channels[$channel]['topic'] = $topic;
        }
    }

    /*
     * =====================================================================================================
     * Get Topic
     * =====================================================================================================
     */
    public function getTopic ($channel)
    {
        if ($channel and isset($this->channels[$channel]['topic']))
        {
            return $this->channels[$channel]['topic'];
        }
        return "";
    }

    /*
     * =====================================================================================================
     * on Private Message handler
     * =====================================================================================================
     */
    private function onPrivMsg ($msg = array())
    {
        // no commands
        if (!count($msg))
            return;

        // get USERs nick
        $nick = $this->getNick($msg[0]);

        // channel (if in private chat, set channel back to user who sent message)
        $channel = $msg[2];
        if ($channel == $this->config['nick'])
            $channel = $nick;

        // log message
        $this->log($channel, $this->filter_log($msg[1], $msg[2], $msg[0], $this->getMsg($msg, 3)));

        // check for bot name to start command
        $name = "";
        if (isset($msg[3]))
            $name = str_replace(array(chr(10), chr(13)), '', $msg[3]);
        if (preg_match('/^:'.$this->config['nick'].'(:|,)/', $name))
        {
            // get command
            $command = "";
            if (isset($msg[4]))
                $command = str_replace(array(chr(10), chr(13)), '', $msg[4]);

            // command parameter
            $param = "";
            if (isset($msg[5]))
                $param = $msg[5];

            // process user commands
            switch ($command)
            {
                case 'help':
                    $this->say($channel, "available commands: (help,insult,page,seen,status,uptime,ver)");
                    break;

                case 'insult':
                    if ($param)
                    {
                        if ($param == $this->config['nick'])
                        {
                            $this->say($channel, "{$this->color('red',$nick)}, Do not even attempt to insult me!!");
                            $this->insult($channel, $nick);
                        }
                        else if ($nick == $param)
                        {
                            $this->say($channel, "{$this->color('red',$nick)}, Why would you want to insult yourself!? Dork!");
                        }
                        else if ($this->isOnline($channel, $param))
                        {
                            if ($this->isAdmin($param))
                            {
                                $this->say($channel, "{{$this->color('red',$nick)}, But {$this->color('yellow',$param)} is one of my dearest friends!");
                            }
                            else
                            {
                                $this->insult($channel, $param);
                            }
                        }
                        else
                        {
                            $this->say($channel, "{$this->color('red',$nick)}, Ummm... {$this->color('red',$param)}, is not online. The insult is on you!");
                            $this->insult($channel, $nick);
                        }
                    }
                    else
                    {
                        $this->say($channel, "{$this->color('red',$nick)}, Doh! You didn't specify who to insult!");
                    }
                    break;

                case 'page':
                    if ($param)
                    {
                        if ($param == $this->config['nick'])
                        {
                            $this->say($channel, "{{$this->color('red',$nick)}, you really do not need to page me. Knob!");
                        }
                        else if ($this->isOnline($channel, $param))
                        {
                            $this->say($channel, "{$this->color('cyan',$nick)}, is already online, go tell them them yourself!");
                        }
                        else if ($this->lastOnline($channel, $param))
                        {
                            $page = $this->getMsg($msg, 6);
                            if ($page)
                            {
                                $this->pages[$param][] = array(
                                                               'from' => $nick,
                                                               'chan' => $channel,
                                                               'page' => $page,
                                                               'time' => time()
                                                              );
                                $this->say($channel, "{$nick}, your page has been stored!");
                            }
                            else
                            {
                                $this->say($channel, "{$nick}, please specify want to you want to page {$param} with!");
                            }
                            unset($page);
                        }
                        else
                        {
                            $this->say($channel, "{$nick}, I do not know who {$param} is! I have never seen them.");
                        }
                    }
                    else
                    {
                        $this->say($channel, "{$nick}, please specify who you want so page!");
                    }
                    break;

                case 'seen':
                    if ($param)
                    {
                        if ($this->isOnline($channel, $param))
                        {
                            $this->say($channel, $this->color('red',$param)." in online in {$channel} and the last post was on ".
                                       $this->color('cyan',date("Y-m-d h:i:s", $this->seen[$param][$channel]['last'])).".");
                        }
                        else if ($this->lastOnline($channel, $param))
                        {
                            $this->say($channel, $this->color('red',$param)." is not currently online in {$channel}. Logged out on ".
                                       $this->color('cyan',date("Y-m-d h:i:s", $this->seen[$param][$channel]['part'])).".");
                        }
                        else
                        {
                            $this->say($channel, $this->color('red',$param)." has never been online in {$channel}.");
                        }
                    }
                    else
                    {
                        $this->say($channel, "please specify who you want so see!");
                    }
                    break;

                case 'uptime':
                    $this->say($channel, $this->color('green',"Online Since: ".date("Y-m-d h:i:s", $this->starttime)));
                    break;

                case 'ver':
                case 'version':
                case 'status':
                    $this->say($channel, $this->color('grey',"==========================================================="));
                    $this->say($channel, " {$this->color('red','ircBot')} by Jeremy Newman <{$this->color('blue','jnewman@codeweavers.com')}>");
                    $this->say($channel, "    version: {$this->color('teal',$this->version)}");
                    $this->say($channel, "    https://github.com/laxdragon/whqIRCbot");
                    $this->say($channel, " {$this->color('green','All Systems Operational!')}");
                    $this->say($channel, " Online Since: {$this->color('lime')}".date("Y-m-d h:i:s", $this->starttime)."{$this->color()}");
                    $this->say($channel, $this->color('grey',"==========================================================="));
                    break;
            }
            // end user commands

            // process admin commands
            if ($this->isAdmin($nick))
            {
                switch ($command)
                {
                    case 'help':
                        $this->say($channel, "available admin commands: (join,quit,op,deop,voice,unvoice,protect,say,topic,timer,who,shutdown)");
                        break;

                    case 'join':
                        if ($param)
                            $this->join_channel($param);
                        break;

                    case 'quit':
                        $this->sendData('QUIT', 'cwBot');
                        $this->disconnect();
                        break;

                    case 'op':
                        $this->changeMode($channel, $param, "o", true);
                        if (!in_array($param, $this->config['admin']))
                            array_push($this->config['admin'], $param);
                        break;

                    case 'deop':
                        $this->changeMode($channel, $param, "o", false);
                        if (in_array($param, $this->config['admin']))
                            $this->config['admin'] = array_merge(array_diff($this->config['admin'], array($param)));
                        break;

                    case 'voice':
                        $this->changeMode($channel, $param, "v", true);
                        break;

                    case 'unvoice':
                        $this->changeMode($channel, $param, "v", false);
                        break;

                    case 'protect':
                        $this->changeMode($channel, $param, "a", true);
                        break;

                    case 'unprotect':
                        $this->changeMode($channel, $param, "a", false);
                        break;

                    case 'say':
                        $in_start = 5;
                        $in_channel = $channel;
                        if (preg_match('/^#/', $param))
                        {
                            $in_start = 6;
                            $in_channel = $param;
                        }
                        $this->say($in_channel, $this->getMsg($msg, $in_start));
                        unset($in_channel, $in_start);
                        break;

                    case 'timer':
                        if ($param == "list")
                        {
                            foreach ($this->timers as $name => $timer)
                            {
                                $this->say($channel, "timer ".$this->color('cyan',"[{$name}]")." ".
                                                     "every ".$this->color('green',"({$timer['secs']})")." seconds.");
                            }
                        }
                        else
                        {
                            $this->runTimers($param);
                        }
                        break;

                    case 'topic':
                        $in_start = 5;
                        $in_channel = $channel;
                        if (preg_match('/^#/', $param))
                        {
                            $in_start = 6;
                            $in_channel = $param;
                        }
                        $this->setTopic($in_channel, $this->getMsg($msg, $in_start));
                        unset($in_channel);
                        break;

                    case 'shutdown':
                        $this->disconnect();
                        exit();

                    case 'who':
                        $in_channel = $channel;
                        if (preg_match('/^#/', $param))
                        {
                            $in_channel = $param;
                        }
                        $this->say($channel, $this->color('grey',str_repeat("-",69)));
                        $this->say($channel, $this->color('grey',"| User           | First Seen       | Last Post        | Is Online  |"));
                        $this->say($channel, $this->color('grey',str_repeat("-",69)));
                        $sep = $this->color('grey',"|");
                        foreach ($this->seen as $usr => $sdata)
                        {
                            if ($usr == $this->config['nick'])
                                continue;
                            if (isset($this->seen[$usr][$in_channel]))
                            {
                                $jo = date('Y-m-d H:i', $this->seen[$usr][$in_channel]['join']);
                                $la = date('Y-m-d H:i', $this->seen[$usr][$in_channel]['last']);
                                $on = ($this->isOnline($in_channel, $usr) ? $this->color('green','yes') : $this->color('red','no '));
                                $this->say($channel, "{$sep} ".$this->color('cyan',$usr).str_repeat(" ", (14 - strlen($usr)))." ".
                                                     "{$sep} {$jo} {$sep} {$la} {$sep} {$on}        {$sep}");
                                unset($jo, $la, $on);
                            }
                        }
                        $this->say($channel, $this->color('grey',str_repeat("-",69)));
                        unset($in_channel, $sep);
                        break;
                }
            }
            // end admin commands
        }
        else
        {
            // Check for user Defined parsers and execute them on defined regex
            foreach ($this->parsers as $parser)
            {
                if ($channel == $parser['chan'] and is_callable($parser['func']))
                {
                    $m = $msg;
                    $m = $this->unsep(implode(" ",array_splice($m, 3)));
                    if (preg_match_all($parser['rexp'], $m, $matches, PREG_SET_ORDER))
                    {
                        echo "-- parser[{$parser['rexp']}] called\n";
                        foreach ($matches as $inMatch)
                        {
                            $this->say($channel, $parser['func']($this, $inMatch));
                        }
                    }
                    unset($m);
                }
            }
        }
        // end commands
    }

    /*
     * =====================================================================================================
     * return IRC color code for english color
     * =====================================================================================================
     */
    public function color ($color = "", $string = "")
    {
        $c = "";
        switch ($color)
        {
            case "bold":
                $c = chr(2);
                break;
            case "black":
                $c = chr(3)."01";
                break;
            case "blue":
                $c = chr(3)."02";
                break;
            case "brown":
            case "maroon":
                $c = chr(3)."05";
                break;
            case "cyan":
            case "aqua":
                $c = chr(3)."11";
                break;
            case "green":
                $c = chr(3)."03";
                break;
            case "grey":
                $c = chr(3)."14";
                break;
            case "lime":
                $c = chr(3)."09";
                break;
            case "orange":
            case "olive":
                $c = chr(3)."07";
                break;
            case "pink":
                $c = chr(3)."13";
                break;
            case "purple":
                $c = chr(3)."06";
                break;
            case "red":
                $c = chr(3)."04";
                break;
            case "royal":
            case "light blue":
                $c = chr(3)."12";
                break;
            case "silver":
                $c = chr(3)."15";
                break;
            case "teal":
                $c = chr(3)."10";
                break;
            case "yellow":
                $c = chr(3)."08";
                break;
            case "reset":
                $c = chr(17);
                break;
            default:
                $c = chr(3);
                break;
        }
        if (!empty($string))
            return $c.$string.chr(3);
        else
            return $c;
    }

    /*
     * =====================================================================================================
     * Output line to HTML log
     * =====================================================================================================
     */
    private function log ($channel, $msg)
    {
        if ($channel and $msg and $this->config['logging'])
        {
            $logpath = rtrim($this->config['log_path'],'/');
            $logdate = date("Ym");
            $logchan = str_replace("#", "", $channel);
            $logfile = fopen("{$logpath}/log-{$logchan}-{$logdate}.html", "a");
            fwrite($logfile, "$msg<br>\n");
            fclose($logfile);
        }
    }

    /*
     * =====================================================================================================
     * Add a Parser Function
     * =====================================================================================================
     */
    public function addParser ($channel, $rexp, $func)
    {
        if (is_string($func))
            echo "-- parser '{$rexp}:{$channel}' registered: {$func}\n";
        else
            echo "-- parser '{$rexp}:{$channel}' registered: {closure}\n";
        $this->parsers[] = array(
                                 'rexp' => $rexp,
                                 'chan' => $channel,
                                 'func' => $func
                                );
    }

    /*
     * =====================================================================================================
     * Add a Timer Function
     * =====================================================================================================
     */
    public function addTimer ($channel, $name, $secs = 0, $func)
    {
        if (!empty($name) and !empty($secs))
        {
            echo "-- timer registered: {$name}:{$channel} => {$secs}\n";
            $this->timers[$name] = array(
                                         'secs' => $secs,
                                         'chan' => $channel,
                                         'func' => $func,
                                         'last' => time()
                                        );
        }
    }

    /*
     * =====================================================================================================
     * Execute Timer Functions
     * =====================================================================================================
     */
    private function runTimers ($runone = "")
    {
        if (!empty($runone))
        {
            // run a single timer
            if (!empty($this->timers[$runone]['func']) and is_callable($this->timers[$runone]['func']))
            {
                $this->timers[$runone]['func']($this, $this->timers[$runone]['chan']);
                $this->timers[$runone]['last'] = time();
            }
        }
        else
        {
            // loop and run all timers
            foreach ($this->timers as $name => $timer)
            {
                // if seconds are 0, skip timer
                if ($timer['secs'] == 0)
                    continue;

                // if timer has elapsed, run
                if (time() - $timer['last'] > $timer['secs'])
                {
                    if (is_callable($timer['func']))
                    {
                        echo "-- calling timer[{$timer['func']}]({$timer['secs']})\n";
                        $timer['func']($this, $this->timers[$name]['chan']);
                        $this->timers[$name]['last'] = time();
                    }
                }
            }
        }
    }

    /*
     * =====================================================================================================
     * SIG handler
     * =====================================================================================================
     */
    private function SIG_handler ($signo)
    {
        switch ($signo)
        {
            // handle shutdown tasks
            case SIGTERM:
                echo "-- SIGTERM: ".date("H:i:s", time())."\n";
                $this->disconnect();
                exit();
                break;

            // handle restart tasks
            case SIGHUP:
                echo "-- SIGHUP: ".date("H:i:s", time())."\n";
                break;
        }
    }

// end ircBot class
}
?>
