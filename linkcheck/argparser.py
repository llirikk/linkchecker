import argparse
import linkcheck
from linkcheck.cmdline import LCArgumentParser
from linkcheck import logconf
has_argcomplete = linkcheck.fileutil.has_module("argcomplete")

# usage texts
Notes = _("""NOTES
 o URLs on the command line starting with "ftp." are treated like
   "ftp://ftp.", URLs starting with "www." are treated like "http://www.".
   You can also give local files as arguments.
 o If you have your system configured to automatically establish a
   connection to the internet (e.g. with diald), it will connect when
   checking links not pointing to your local system.
   See the --ignore-url option on how to prevent this.
 o Javascript links are currently ignored.
 o If your platform does not support threading, LinkChecker disables it
   automatically.
 o You can supply multiple user/password pairs in a configuration file.
 o When checking 'news:' links the given NNTP host doesn't need to be the
   same as the host of the user browsing your pages.
""")

ProxySupport = _("""PROXY SUPPORT
To use a proxy on Unix or Windows set $http_proxy, $https_proxy or $ftp_proxy
to the proxy URL. The URL should be of the form
"http://[<user>:<pass>@]<host>[:<port>]".
LinkChecker also detects manual proxy settings of Internet Explorer under
Windows systems, and gconf or KDE on Linux systems.
On a Mac use the Internet Config to select a proxy.

LinkChecker honors the $no_proxy environment variable. It can be a list
of domain names for which no proxy will be used.

Setting a HTTP proxy on Unix for example looks like this:

  export http_proxy="http://proxy.example.com:8080"

Proxy authentication is also supported:

  export http_proxy="http://user1:mypass@proxy.example.org:8081"

Setting a proxy on the Windows command prompt:

  set http_proxy=http://proxy.example.com:8080

""")

RegularExpressions = _("""REGULAR EXPRESSIONS
Only Python regular expressions are accepted by LinkChecker.
See http://www.amk.ca/python/howto/regex/ for an introduction in
regular expressions.

The only addition is that a leading exclamation mark negates
the regular expression.
""")

CookieFormat = _("""COOKIE FILES
A cookie file contains standard RFC 805 header data with the following
possible names:
Scheme (optional)
 Sets the scheme the cookies are valid for; default scheme is 'http'.
Host (required)
 Sets the domain the cookies are valid for.
Path (optional)
 Gives the path the cookies are value for; default path is '/'.
Set-cookie (optional)
 Set cookie name/value. Can be given more than once.

Multiple entries are separated by a blank line.

The example below will send two cookies to all URLs starting with
'http://example.org/hello/' and one to all URLs starting
with 'https://example.com/':

Host: example.org
Path: /hello
Set-cookie: ID="smee"
Set-cookie: spam="egg"

Scheme: https
Host: example.com
Set-cookie: baggage="elitist"; comment="hologram"
""")

Retval = _(r"""RETURN VALUE
The return value is non-zero when
 o invalid links were found or
 o warnings were found warnings are enabled
 o a program error occurred
""")

Examples = _(r"""EXAMPLES
The most common use checks the given domain recursively, plus any
single URL pointing outside of the domain:
  linkchecker http://www.example.org/
Beware that this checks the whole site which can have several hundred
thousands URLs. Use the -r option to restrict the recursion depth.

Don't connect to mailto: hosts, only check their URL syntax. All other
links are checked as usual:
  linkchecker --ignore-url=^mailto: www.example.org

Checking local HTML files on Unix:
  linkchecker ../bla.html subdir/blubber.html

Checking a local HTML file on Windows:
  linkchecker c:\temp\test.html

You can skip the "http://" url part if the domain starts with "www.":
  linkchecker www.example.de

You can skip the "ftp://" url part if the domain starts with "ftp.":
  linkchecker -r0 ftp.example.org
""")

LoggerTypes = _(r"""OUTPUT TYPES
Note that by default only errors and warnings are logged.
You should use the --verbose option to see valid URLs,
and when outputting a sitemap graph format.

text    Standard text output, logging URLs in keyword: argument fashion.
html    Log URLs in keyword: argument fashion, formatted as HTML.
        Additionally has links to the referenced pages. Invalid URLs have
        HTML and CSS syntax check links appended.
csv     Log check result in CSV format with one URL per line.
gml     Log parent-child relations between linked URLs as a GML sitemap
        graph.
dot     Log parent-child relations between linked URLs as a DOT sitemap
        graph.
gxml    Log check result as a GraphXML sitemap graph.
xml     Log check result as machine-readable XML.
sql     Log check result as SQL script with INSERT commands. An example
        script to create the initial SQL table is included as create.sql.
blacklist
        Suitable for cron jobs. Logs the check result into a file
        ~/.linkchecker/blacklist which only contains entries with invalid
        URLs and the number of times they have failed.
none    Logs nothing. Suitable for debugging or checking the exit code.
""")

Warnings = _(r"""IGNORE WARNINGS
The following warnings are recognized in the 'ignorewarnings' config
file entry:
""") + \
"\n".join([" o %s - %s" % (tag, desc) \
           for tag, desc in sorted(linkcheck.checker.const.Warnings.items())])

Epilog = "\n".join((Examples, LoggerTypes, RegularExpressions, CookieFormat, ProxySupport, Notes, Retval, Warnings))

argparser = LCArgumentParser(
  epilog=Epilog,
  formatter_class=argparse.RawDescriptionHelpFormatter
)

################# general options ##################
group = argparser.add_argument_group(_("General options"))
group.add_argument("-f", "--config", dest="configfile",
                 metavar="FILENAME",
                 help=_(
"""Use FILENAME as configuration file. Per default LinkChecker uses
~/.linkchecker/linkcheckerrc (under Windows
%%HOMEPATH%%\\.linkchecker\\linkcheckerrc)."""))
group.add_argument("-t", "--threads", type=int, metavar="NUMBER",
                 help=_(
"""Generate no more than the given number of threads. Default number
of threads is 10. To disable threading specify a non-positive number."""))
group.add_argument("-V", "--version", action="store_true",
                 help=_("""Print version and exit."""))
group.add_argument("--list-plugins", action="store_true", dest="listplugins",
                 help=_(
"""Print available check plugins and exit."""))
group.add_argument("--stdin", action="store_true",
                 help=_(
"""Read list of white-space separated URLs to check from stdin."""))

################# output options ##################
group = argparser.add_argument_group(_("Output options"))
# XXX deprecated: --check-css moved to plugin CssSyntaxCheck
group.add_argument("--check-css", action="store_true", dest="checkcss",
                 help=argparse.SUPPRESS)
# XXX deprecated: --check-html moved to plugin HtmlSyntaxCheck
group.add_argument("--check-html", action="store_true", dest="checkhtml",
                 help=argparse.SUPPRESS)
# XXX deprecated: --complete is removed
group.add_argument("--complete", action="store_true", dest="complete",
                 help=argparse.SUPPRESS)
group.add_argument("-D", "--debug", action="append", metavar="STRING",
                 help=_("""Print debugging output for the given logger.
Available loggers are %(lognamelist)s.
Specifying 'all' is an alias for specifying all available loggers.
The option can be given multiple times to debug with more
than one logger.

For accurate results, threading will be disabled during debug runs.""") % \
{"lognamelist": logconf.lognamelist})
group.add_argument("-F", "--file-output", action="append",
                 dest="fileoutput", metavar="TYPE[/ENCODING[/FILENAME]]",
                 help=_(
"""Output to a file linkchecker-out.TYPE, $HOME/.linkchecker/blacklist for
'blacklist' output, or FILENAME if specified.
The ENCODING specifies the output encoding, the default is that of your
locale.
Valid encodings are listed at http://docs.python.org/lib/standard-encodings.html.
The FILENAME and ENCODING parts of the 'none' output type will be ignored,
else if the file already exists, it will be overwritten.
You can specify this option more than once. Valid file output types
are %(loggertypes)s. You can specify this option multiple times to output
to more than one file. Default is no file output. Note that you can
suppress all console output with the option '-o none'.""") % \
{'loggertypes': linkcheck.logger.LoggerKeys})
group.add_argument("--no-status", action="store_false", dest="status",
                 default=True, help=_(
"""Do not print check status messages."""))
group.add_argument("--no-warnings", action="store_false", dest="warnings",
                help=_("""Don't log warnings. Default is to log warnings."""))
group.add_argument("-o", "--output", dest="output", metavar="TYPE[/ENCODING]",
                 help=_(
"""Specify output as %(loggertypes)s. Default output type is text.
The ENCODING specifies the output encoding, the default is that of your
locale.
Valid encodings are listed at """ \
"""http://docs.python.org/lib/standard-encodings.html.""") % \
{'loggertypes': linkcheck.logger.LoggerKeys})
group.add_argument("--profile", action="store_true", dest="profile",
                 help=argparse.SUPPRESS)
group.add_argument("-q", "--quiet", action="store_true", dest="quiet",
                 help=_(
"""Quiet operation, an alias for '-o none'.
This is only useful with -F."""))
# XXX deprecated: moved to plugin VirusCheck
group.add_argument("--scan-virus", action="store_true", dest="scanvirus",
                 help=argparse.SUPPRESS)
group.add_argument("--trace", action="store_true", dest="trace",
                 help=argparse.SUPPRESS)
group.add_argument("-v", "--verbose", action="store_true", dest="verbose",
                 help=_(
"""Log all URLs. Default is to log only errors and warnings."""))
# XXX deprecated: moved to plugin RegexCheck
group.add_argument("-W", "--warning-regex", dest="warningregex",
                 metavar="REGEX",
                 help=argparse.SUPPRESS)
# XXX deprecated: removed
group.add_argument("--warning-size-bytes", dest="warningsizebytes",
                 metavar="NUMBER",
                 help=argparse.SUPPRESS)


################# checking options ##################
group = argparser.add_argument_group(_("Checking options"))
# XXX deprecated: moved to plugin AnchorCheck
group.add_argument("-a", "--anchors", action="store_true", dest="anchors",
                 help=argparse.SUPPRESS)
# XXX deprecated: replaced with requests session cookie handling
group.add_argument("-C", "--cookies", action="store_true", dest="cookies",
                 help=argparse.SUPPRESS)
group.add_argument("--cookiefile", dest="cookiefile", metavar="FILENAME",
                 help=_(
"""Read a file with initial cookie data. The cookie data format is
explained below."""))
# const because store_false doesn't detect absent flags
group.add_argument("--no-robots", action="store_const", const=False,
                   dest="norobotstxt", help=_("Disable robots.txt checks"))
group.add_argument("--check-extern", action="store_true",
                 dest="checkextern", help=_("""Check external URLs."""))
group.add_argument("--ignore-url", action="append", metavar="REGEX",
                 dest="externstrict", help=_(
"""Only check syntax of URLs matching the given regular expression.
 This option can be given multiple times."""))
group.add_argument("--no-follow-url", action="append", metavar="REGEX",
                 dest="extern", help=_(
"""Check but do not recurse into URLs matching the given regular
expression. This option can be given multiple times."""))
group.add_argument("-N", "--nntp-server", dest="nntpserver", metavar="STRING",
                 help=_(
"""Specify an NNTP server for 'news:...' links. Default is the
environment variable NNTP_SERVER. If no host is given,
only the syntax of the link is checked."""))
group.add_argument("-p", "--password", action="store_false", dest="password",
                 default=False,
                 help=_(
"""Read a password from console and use it for HTTP and FTP authorization.
For FTP the default password is 'anonymous@'. For HTTP there is
no default password. See also -u."""))
# XXX deprecated: replaced with numrequestsperpage
group.add_argument("-P", "--pause", type=int, dest="pause",
                 metavar="NUMBER",
                 help=argparse.SUPPRESS)
group.add_argument("-r", "--recursion-level", type=int,
                 dest="recursionlevel", metavar="NUMBER",
                 help=_(
"""Check recursively all links up to given depth. A negative depth
will enable infinite recursion. Default depth is infinite."""))
group.add_argument("--timeout", type=int, dest="timeout",
                 metavar="NUMBER",
                 help=_(
"""Set the timeout for connection attempts in seconds. The default
timeout is %d seconds.""") % 918248234 )  # TODO config
group.add_argument("-u", "--user", dest="username", metavar="STRING",
                 help=_(
"""Try the given username for HTTP and FTP authorization.
For FTP the default username is 'anonymous'. For HTTP there is
no default username. See also -p."""))
group.add_argument("--user-agent", dest="useragent", metavar="STRING",
                 help=_(
"""Specify the User-Agent string to send to the HTTP server, for example
"Mozilla/4.0". The default is "LinkChecker/X.Y" where X.Y is the current
version of LinkChecker."""))

argparser.add_argument('url', nargs='*')
################# auto completion #####################
if has_argcomplete:
    import argcomplete
    argcomplete.autocomplete(argparser)
