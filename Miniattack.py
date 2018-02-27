# coding=utf-8

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation;
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
# Created by Bodo Brand
# 28. February 2018 - version number 1.0.0

MINIATTACK_VERSION = "1.0.0"

import struct, fcntl, termios, signal, sys, os, click, re

from mininet.topo import Topo
from mininet.nodelib import LinuxBridge
from mininet.node import Host
from mininet.term import makeTerm
from mininet.net import VERSION
from mininet.net import Mininet
from mininet.node import Host, NullController
from mininet.link import Link

from mininet.log import lg, LEVELS, info, debug, warn, error

import MiniNAM

import threading

from time import sleep, time
import errno

"""
    When started without any options a classic Attack Topology is loaded:
    Alice (h1), Bob (h2), Eve (h3) Topology with one LinuxBridge.
"""
#locations = {'s1':(450,200), 'h1':(200,200),'h2':(700,200),'h3':(450,350)}

#topos = {'mytopo': (lambda: Topologies.SingleLxbrTopo(n=3))}

# Allow -h or --help for usage/help
CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])

def print_version(ctx, param, value):
    """
        print MiniNAM, Mininet and Miniattack version.
    """
    # Define versions as parameters (make versions accessible for the rest of the application)
    ctx.params["mininam_version"] = MiniNAM.MININAM_VERSION
    ctx.params["mininet_version"] = re.sub(r'[^\d\.]', '', VERSION)
    ctx.params["miniattack_version"] = MINIATTACK_VERSION
    # http://click.pocoo.org/5/options/#callbacks-and-eager-options
    if not value or ctx.resilient_parsing:
        return
    click.echo(ctx.info_name + ", version " + ctx.params["miniattack_version"] + "\nMininet, version " + ctx.params["mininet_version"] + "\nMiniNAM, version " + ctx.params["mininam_version"])
    ctx.exit()


@click.group(context_settings=CONTEXT_SETTINGS)
@click.option("--version", default=False, is_flag=True, callback=print_version, expose_value=False, is_eager=True)
@click.option("--verbosity", "-v", default="info", type=click.Choice(LEVELS.keys()), help="set Verbosity/Debug Level")
def cli(**kwargs):
    # Set Verbosity Level
    lg.setLogLevel(kwargs["verbosity"])
    pass

class TopologyHelper:
    """
    This class will let you create Mininet Topologies with ease.
    e.g.
    topo = TopologyHelper.SingleLxbrTopo(n=3)
    net = topo.start()
    """

    class SingleLxbrTopo(Topo):
        "Single LinuxBridge connected to n hosts."

        # optional default values (can be used by MiniNAMHelper)
        locations = {'s1':(450,200), 'h1':(200,200),'h2':(700,200),'h3':(450,350)}

        def build(self, n=2):
            switch = self.addSwitch('s1', cls=LinuxBridge)
            for h in range(n):
                host = self.addHost('h%s' % (h + 1), cls=Host, ip='10.0.0.%s' % (h + 1), defaultRoute=None)
                self.addLink(host, switch)

        def start(self):
            _net = Mininet

            net = _net(topo=self,
                       switch=LinuxBridge,  # options: UserSwitch, OVSSwitch, OVSBridge, IVSSwitch
                       host=Host,  # Also CPU Limited Hosts possible
                       # options: RemoteController, findController, DefaultController, NullController,
                       #          Controller, OVSController, Ryu, NOX,
                       controller=NullController,
                       link=Link,  # options: Link, TCLink, OVSLink, TCULink
                       ipBase='10.0.0.0/8',
                       inNamespace=False,
                       xterms=False,  # Spawn xterms for each node
                       autoSetMacs=False,  # Automatically sets MAC Addresses for Hosts
                       autoStaticArp=False,
                       autoPinCpus=False,  # Requires CPU Limited Hosts
                       listenPort=6634)  # Passive Switch listening (only for SDNs

            net.start()

            return net

class MiniNAMHelper:
    """
    This Class will let you start MiniNAM and have access to important variables.
    Only use self.app when self.ready is True. It is recommended to only use methods in MiniNAM
    which starts with "run". e.g. runCreateSubWindow let you create Sub Windows during runtime.
    """

    app = None
    ready = threading.Event() # When this flag is set
    thread = None # MiniNAM thread
    locations = None

    def defaultStart(self, net, locations, initfunc, width=1280, height=720):
        """
            Starts the MiniNAM GUI.

            From MiniNAM 1.0.1 README:
            'By default, MiniNAM uses packet type, source and destination address to identify flows.'

            :param width: width of MiniNAM Window
            :param height: height of MiniNAM Window
            :param net: Already startet Mininet net instance
            :param locations: Dictionary with Node locations in GUI
            :param winwinfunc: a function which gets the MiniNAM Window as parameter and executes before mainloop
            :return thread
        """
        self.locations = locations
        self.app = None # Expose created gui object
        self.thread = threading.Thread(target=MiniNAMHelper.defaultStart_threaded, name="MiniNAM", args=(self, net, locations, initfunc, width, height))
        self.thread.start()

    def defaultStart_threaded(self, net, locations, initfunc, width, height):
        try:
            self.app = MiniNAM.MiniNAM(cwidth=width, cheight=height, net=net, locations=locations, SubWinEvents=False)

            self.app.update()

            # Calls your custom function
            initfunc(self.app)

            self.app.subWinEventsStart()

            # enable creation of SubWindows during runtime with runCreateSubWindow
            self.app.createSubWinLoop()

            self.app.update()

            self.app.after(500, self.ready.set()) # GUI is ready

            self.app.mainloop()

        except KeyboardInterrupt:
            info("\n\nKeyboard Interrupt. Shutting down and cleaning up...\n\n")
            self.app.stop()

        except Exception:
            # Print exception
            type_, val_, trace_ = sys.exc_info()
            line = sys.exc_info()[-1].tb_lineno
            errorMsg = ("-" * 80 + "\n" +
                        "Caught exception on line %d." % (line) +
                        " Cleaning up...\n\n" + "%s: %s\n" % (type_.__name__, val_) +
                        "-" * 80 + "\n")
            error(errorMsg)
            # Print stack trace to debug log
            import traceback

            stackTrace = traceback.format_exc()
            debug(stackTrace + "\n")
            self.app.stop()

    def WinWin_xterm_custom(self, command):
        """
        Creates a xterm with custom command in the SubWindow.

        This method is supposed to be used as contentfunc argument when calling
        runCreateSubWindow during runtime.

        :return: a method which is supposed to be used as contentfunc argument.
        """
        def SubWin_xterm_custom(main_frame, node):
            from mininet.term import tunnelX11

            tunnelX11(node)
            cmd = r"""xterm -into """ + str(main_frame.winfo_id()) + r""" -e '""" + command + r"""; bash' &"""

            node.cmd(cmd)

        return SubWin_xterm_custom

    def WinWin_run(self, host, command, delay=10, width=350, height=250, posx=None, posy=None, destroy=0):
        """
        A convenience method which starts a Sub Window next to host
        and executes command inside an xterm after delay seconds.

        :param host: Host as String e.g. "h1"
        :param command: bash command as STring e.g. "ping -c 1 10.0.0.2"
        :param delay: delay in seconds e.g. 3 or 0.5
        :param destroy: destroy's Sub Window after destroy seconds. '0' does not destroy SubWindow.
        """

        # Figure out a good position for SubWindow
        if not posx or not posy:
            # get all positions
            host_pos = self.locations[host]
            if not host_pos:
                lg.error("no location for host %s defined" % (host))
                return
            # put window on Bottom of Host
            if not posx:
                posx = host_pos[0] - (width / 2)
            if not posy:
                posy = host_pos[1] + 80

        if delay:
            cmd = "termdown --no-figlet -W -f big -T \"" + command.split(";")[0].replace('"','\\"') + "\" " + str(delay) + "; sleep 0.1; " + command

        subWinReady = threading.Event()
        subWin = [None]
        self.app.runCreateSubWindow(width=width, height=height, posx=posx, posy=posy, contentfunc=self.WinWin_xterm_custom(cmd), host=host, events=True, subWinReady=subWinReady, subWin=subWin)

        subWinReady.wait()
        # wait until SubWindow ready
        if delay:
            sleep(delay+0.1)

        if destroy:
            sleep(destroy)
            self.app.runDestroySubWindow(subWin[0])

class ProcessHelper:

    @staticmethod
    def executeGetPid(host, cmd, verbose=False):
        """
        Execute any cmd on any host and return the pid instantly.
        Make sure you start the cmd in background, otherwise the process is blocking.
        You can kill or show the command through Mininet CLI:

        # global
        *soft kill :: mininet> sh kill pid
        *hard kill :: mininet> sh kill -9 pid

        # host specific
        *show jobs from Host h1 :: mininet> h1 jobs
        *kill first job from Host h1 :: mininet> h1 kill %1


        :param host: a Mininet Host Object
        :param cmd: Shell Command to execute. e.g. 'sleep 1000 &'
        :return: PID or on error no PID
        """
        out = host.cmd(cmd)
        pid = int(host.cmd('echo $!'))
        if not pid:
            print "execution failed, output:\n%s" % (out)
        if verbose:
            print "%s exec: %s (pid: %d)" % (host, cmd, pid)
        return pid

class PexpectMiniNAM:
    """
    This Class demonstrates an example to start any MiniNAM version
    with pexpect and automatically import Miniattack.py into the Mininet CLI
    for interactive usage.
    """

    @staticmethod
    def init(_net):
        """
        Will be executed when the module got loaded in
        mininet CLI.

        :param _net: started Mininet Instance will be passed
        :return:
        """
        # Make Mininet Instance globally available for interactive usage.
        global net
        net = _net

        print "Miniattack successfully loaded!"

    @staticmethod
    def sigwinch_passthrough(sig, data):
        """
        Passes sigwinch signals to the child process of pexpect.spawn.
        Enables resizing of the window.
        """
        s = struct.pack("HHHH", 0, 0, 0, 0)
        a = struct.unpack('hhhh', fcntl.ioctl(sys.stdout.fileno(),
                                              termios.TIOCGWINSZ, s))
        global child
        child.setwinsize(a[0], a[1])

    @staticmethod
    def start():
        """
        Starts MiniNAM with pexpect and imports this script into Mininet CLI.
        """
        import pexpect

        # GET CURRENT DIRECTORY
        dir_path = os.path.dirname(os.path.realpath(__file__))

        COMMAND_PROMPT = 'mininet>'

        # child = pexpect.spawn('mn')
        child = pexpect.spawn(
            'python MiniNAM.py -v debug --config conf.config --custom Miniattack.py --topo mytopo --controller none')

        # Log everything in stdout
        child.logfile = sys.stdout

        try:
            child.expect(COMMAND_PROMPT, timeout=10)
        except pexpect.TIMEOUT:
            lg.fatal("Can't find mininet CLI. Missing '\"startCLI\": 1' in conf.config?\n")
            child.close()
            exit(1)
        child.sendline('px sys.path.append("' + dir_path + '")')
        child.expect(COMMAND_PROMPT, timeout=10)
        child.sendline('px from ' + __name__ + ' import *')
        child.expect(COMMAND_PROMPT, timeout=10)
        child.sendline('py PexpectMiniNAM.init(net)')

        # disable log file
        child.logfile = None
        # enables the window resizing to work properly
        signal.signal(signal.SIGWINCH, PexpectMiniNAM.sigwinch_passthrough)

        child.interact()

        print "Left interactive mode."

# set topology and locations for pexpect here
topos = {'mytopo': (lambda: TopologyHelper.SingleLxbrTopo(n=3))}
locations = {'s1':(450,200), 'h1':(200,200),'h2':(700,200),'h3':(450,350)}

@click.command(context_settings=CONTEXT_SETTINGS)
def pexpect_experimental():
    PexpectMiniNAM.start()

@click.command(context_settings=CONTEXT_SETTINGS)
@click.option("--width", "-w", default=1280, type=int, help="width of MiniNAM window")
@click.option("--height", "-h", default=720, type=int, help="height of MiniNAM window")
def arpspoof(**kwargs):
    """
    Demonstrates an arp spoofing attack.
    """
    # Create Mininet from Miniattack preset with default locations
    topo = TopologyHelper.SingleLxbrTopo(n=3)
    # Startup Code for a Mininet is included in the Topology Preset
    net = topo.start()

    # Prepare MiniNAM
    # init will be executed during startup
    def init(app):

        # Create xterm Window in Window (watching the arp table)
        def SubWin_xterm_create(main_frame, node):
            from mininet.term import tunnelX11

            tunnelX11(node)
            # execute 'arp' every 2 seconds
            #node.cmd("xterm -into %d -e \"watch arp; bash\" &" % main_frame.winfo_id())
            # additionally filters IP address and MAC address column
            cmd = r"""xterm -into """+str(main_frame.winfo_id())+r""" -e $'watch --color --no-title \"arp|awk \'{ \$2=\\"\\";\$4=\\"\\";\$5=\\"\\";\$6=\\"\\";print}\'|column -t\"; bash' &"""
            node.cmd(cmd)

        app.createSubWindow(250, 100, 50, 50, SubWin_xterm_create, "h1")
        app.createSubWindow(250, 100, 600, 50, SubWin_xterm_create, "h2")


    # Startup MiniNAM (non blocking)
    MiniNAM = MiniNAMHelper()
    MiniNAM.defaultStart(net, topo.locations, init, kwargs["width"], kwargs["height"])

    start_time = time()

    MiniNAM.ready.wait() # blocking until ready is true
    lg.info("MiniNAM took %s seconds to start" % (time() - start_time))

    # DURING RUNTIME
    sleep(3)
    h1, h2, h3 = net.get("h1"), net.get("h2"), net.get("h3")

    # explain topology
    explaination = """
    h1:
    IP: """ + h1.IP() + """   MAC: """ + h1.MAC()+ """
    
    h2:
    IP: """ + h2.IP() + """   MAC: """ + h2.MAC()+ """
    
    h3:
    IP: """ + h3.IP() + """   MAC: """ + h3.MAC()+ """
    """
    MiniNAM.WinWin_run("h3",
                       'echo README; printf "'+explaination+'"',
                       delay=5, height=170, posx=900, posy=50, destroy=0)

    MiniNAM.WinWin_run("h1","ping -c 1 10.0.0.2", delay=5, height=150, destroy=5)

    MiniNAM.WinWin_run("h2", "ping -c 1 10.0.0.1", delay=5, height=150, destroy=5)

    sleep(7)
    # Enable IPv4 Forwarding on h3
    #h3.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")
    MiniNAM.WinWin_run("h3", "echo 1 > /proc/sys/net/ipv4/ip_forward; printf \"IPV4 Forwarding is enabled!\n\"",
                       delay=5, height=150, posx=900, posy=300, destroy=0)

    sleep(2)
    cmd = "arpspoof -i " + str(h3.intfs[0]) + " -t " + h1.IP() + " " + h2.IP()
    MiniNAM.WinWin_run("h3", cmd, delay=5, height=100, posx=90, posy=470)
    sleep(5)
    cmd = "arpspoof -i " + str(h3.intfs[0]) + " -t " + h2.IP() + " " + h1.IP()
    MiniNAM.WinWin_run("h3", cmd, delay=5, height=100, posx=460, posy=470)
    sleep(5)
    MiniNAM.WinWin_run("h1", "ping -c 1 10.0.0.2", delay=5, height=150, destroy=0)

    MiniNAM.WinWin_run("h2", "ping -c 1 10.0.0.1", delay=5, height=150, destroy=0)

    MiniNAM.thread.join()



# start MiniNAM with pexpect
cli.add_command(pexpect_experimental)
# Add all Attacks here.
cli.add_command(arpspoof)


if __name__ == '__main__':
    cli()


