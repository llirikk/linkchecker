#!/usr/bin/python3 -u
# Copyright (C) 2000-2014 Bastian Kleineidam
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
"""
Check HTML pages for broken links. This is the commandline
client. Run this file with the -h option to see how it's done.
"""
from utils import Map
def main(options):
    import sys
    import codecs
    import os
    import pprint
    import getpass
    # installs _() and _n() gettext functions into global namespace
    import linkcheck
    from linkcheck import logconf, LOG_CMDLINE
    logconf.init_log_config()
    # override argparse gettext method with the one from linkcheck.init_i18n()
    #argparse._ = _
    # now import the rest of the linkchecker gang
    from linkcheck.cmdline import print_version, print_usage, aggregate_url, \
    LCArgumentParser, print_plugins
    from linkcheck import log, i18n, strformat
    import linkcheck.checker
    import linkcheck.configuration
    import linkcheck.fileutil
    import linkcheck.logger
    import linkcheck.ansicolor
    from linkcheck.director import console, check_urls, get_aggregate


    # optional modules

    has_profile = linkcheck.fileutil.has_module("yappi")
    has_meliae = linkcheck.fileutil.has_module("meliae")

    # default profiling filename
    _profile = "linkchecker.prof"
    _username = None
    _password = None

    def has_encoding(encoding):
        """Detect if Python can encode in a certain encoding."""
        try:
            codecs.lookup(encoding)
            return True
        except LookupError:
            return False

    # build a config object for this check session
    config = linkcheck.configuration.Configuration()
    config.set_status_logger(console.StatusLogger())

    def read_stdin_urls():
        """Read list of URLs, separated by white-space, from stdin."""
        num = 0
        while True:
            lines = sys.stdin.readlines(8 * 1024)
            if not lines:
                break
            for line in lines:
                for url in line.split():
                    num += 1
                    if num % 10000 == 0:
                        log.info(LOG_CMDLINE, "Read %d URLs from stdin", num)
                    yield url


    # read and parse command line options and arguments

    # initialize logging
    if options.debug:
        allowed_debugs = logconf.lognames.keys()
        for _name in options.debug:
            if _name not in allowed_debugs:
                print_usage(_("Invalid debug level %(level)r") % {'level': _name})
        logconf.set_debug(options.debug)
    log.debug(LOG_CMDLINE, _("Python %(version)s on %(platform)s") % \
    {"version": sys.version, "platform": sys.platform})
    # read configuration files
    try:
        files = []
        if options.configfile:
            path = linkcheck.configuration.normpath(options.configfile)
            if os.path.isfile(path):
                files.append(path)
            else:
                log.warn(LOG_CMDLINE,
                        _("Unreadable config file: %r"), options.configfile)
        config.read(files=files)
    except linkcheck.LinkCheckerError as msg:
        # config error
        print_usage(str(msg))
    linkcheck.drop_privileges()
    # test if running with -O
    if options.debug and not __debug__:
        log.warn(LOG_CMDLINE, _("Running with python -O disables debugging."))
    # apply commandline options and arguments to configuration
    constructauth = False
    do_profile = False
    if options.version:
        print_version()
    if not options.warnings:
        config["warnings"] = options.warnings
    if options.externstrict:
        pats = [linkcheck.get_link_pat(arg, strict=True) \
                for arg in options.externstrict]
        config["externlinks"].extend(pats)
    if options.extern:
        pats = [linkcheck.get_link_pat(arg) for arg in options.extern]
        config["externlinks"].extend(pats)
    if options.norobotstxt is not None:
        config['robotstxt'] = options.norobotstxt
    if options.checkextern:
        config["checkextern"] = True
    elif not config["checkextern"]:
        log.info(LOG_CMDLINE, "Checking intern URLs only; use --check-extern to check extern URLs.")

    if options.output:
        if "/" in options.output:
            logtype, encoding = options.output.split("/", 1)
        else:
            logtype, encoding = options.output, i18n.default_encoding
        logtype = logtype.lower()
        if logtype not in linkcheck.logger.LoggerNames:
            print_usage(
        _("Unknown logger type %(type)r in %(output)r for option %(option)s") % \
        {"type": logtype, "output": options.output, "option": "'-o, --output'"})
        if logtype != 'none' and not has_encoding(encoding):
            print_usage(
        _("Unknown encoding %(encoding)r in %(output)r for option %(option)s") % \
        {"encoding": encoding, "output": options.output,
        "option": "'-o, --output'"})
        config['output'] = logtype
        config['logger'] = config.logger_new(logtype, encoding=encoding)
    if options.fileoutput:
        ns = {'fileoutput': 1}
        for arg in options.fileoutput:
            ftype = arg
            # look for (optional) filename and encoding
            if '/' in ftype:
                ftype, suffix = ftype.split('/', 1)
                if suffix:
                    if has_encoding(suffix):
                        # it was an encoding
                        ns['encoding'] = suffix
                    elif '/' in suffix:
                        # look for (optional) encoding
                        encoding, filename = suffix.split('/', 1)
                        if has_encoding(encoding):
                            ns['encoding'] = encoding
                            ns['filename'] = filename
                        else:
                            ns['filename'] = suffix
                    else:
                        ns['filename'] = suffix
            if ftype not in linkcheck.logger.LoggerNames:
                print_usage(
        _("Unknown logger type %(type)r in %(output)r for option %(option)s") % \
        {"type": ftype, "output": options.fileoutput,
            "option": "'-F, --file-output'"})
            if ftype != 'none' and 'encoding' in ns and \
            not has_encoding(ns['encoding']):
                print_usage(
        _("Unknown encoding %(encoding)r in %(output)r for option %(option)s") % \
        {"encoding": ns['encoding'], "output": options.fileoutput,
        "option": "'-F, --file-output'"})
            logger = config.logger_new(ftype, **ns)
            config['fileoutput'].append(logger)
    if options.nntpserver:
        config["nntpserver"] = options.nntpserver
    if options.username:
        _username = options.username
        constructauth = True
    if options.password:
        if _username:
            msg = _("Enter LinkChecker HTTP/FTP password for user %(user)s:") % \
                {"user": _username}
        else:
            msg = _("Enter LinkChecker HTTP/FTP password:")
        _password = getpass.getpass(console.encode(msg))
        constructauth = True
    if options.profile:
        do_profile = options.profile
    if options.quiet:
        config['logger'] = config.logger_new('none')
    if options.recursionlevel is not None:
        config["recursionlevel"] = options.recursionlevel
    if options.status:
        config['status'] = options.status
    if options.threads is not None:
        if options.threads < 1:
            options.threads = 0
        config["threads"] = options.threads
    if options.timeout is not None:
        if options.timeout > 0:
            config["timeout"] = options.timeout
        else:
            print_usage(_("Illegal argument %(arg)r for option %(option)s") % \
                        {"arg": options.timeout, "option": "'--timeout'"})
    if options.listplugins:
        print_plugins(config["pluginfolders"])
    if options.verbose:
        if options.verbose:
            config["verbose"] = True
            config["warnings"] = True
    if options.cookiefile is not None:
        config['cookiefile'] = options.cookiefile
    if constructauth:
        config.add_auth(pattern=".+", user=_username, password=_password)
    # read missing passwords
    for entry in config["authentication"]:
        if entry["password"] is None:
            attrs = entry.copy()
            attrs["strpattern"] = attrs["pattern"].pattern
            msg = _("Enter LinkChecker password for user %(user)s" \
                    " at %(strpattern)s:") % attrs
            entry["password"] = getpass.getpass(msg)
    if options.useragent is not None:
        config["useragent"] = options.useragent
    if options.cookiefile is not None:
        if linkcheck.fileutil.is_readable(options.cookiefile):
            config["cookiefile"] = options.cookiefile
        else:
            msg = _("Could not read cookie file %s") % options.cookiefile
            log.error(LOG_CMDLINE, msg)
    # now sanitize the configuration
    config.sanitize()

    log.debug(LOG_CMDLINE, "configuration: %s",
            pprint.pformat(sorted(config.items())))

    # prepare checking queue
    aggregate = get_aggregate(config)
    if options.trace:
        # enable thread tracing
        config["trace"] = True
        # start trace in mainthread
        import linkcheck.trace
        linkcheck.trace.trace_filter([r"^linkcheck"])
        linkcheck.trace.trace_on()
    # add urls to queue
    if options.stdin:
        for url in read_stdin_urls():
            aggregate_url(aggregate, url)
    elif options.url:
        for url in options.url:
            aggregate_url(aggregate, strformat.stripurl(url))
    else:
        log.warn(LOG_CMDLINE, _("no files or URLs given"))
    # set up profiling
    if do_profile:
        if has_profile:
            if os.path.exists(_profile):
                print(_("""Overwrite profiling file %(file)r?
    Press Ctrl-C to cancel, RETURN to continue.""") % {"file": _profile})
                try:
                    input()
                except KeyboardInterrupt:
                    print("", _("Canceled."), file=sys.stderr, sep="\n")
                    sys.exit(1)
        else:
            log.warn(LOG_CMDLINE,
                    _("The `yappi' Python module is not installed,"
                        " therefore the --profile option is disabled."))
            do_profile = False

    # finally, start checking
    if do_profile:
        import yappi
        yappi.start()
        check_urls(aggregate)
        yappi.stop()
        yappi.get_func_stats().save(_profile)
    else:
        check_urls(aggregate)
    if config["debugmemory"]:
        import linkcheck.memoryutil
        if has_meliae:
            log.info(LOG_CMDLINE, _("Dumping memory statistics..."))
            filename = linkcheck.memoryutil.write_memory_dump()
            message = _("The memory dump has been written to `%(filename)s'.")
            log.info(LOG_CMDLINE, message % dict(filename=filename))
        else:
            log.warn(LOG_CMDLINE, linkcheck.memoryutil.MemoryDebugMsg)

    stats = config['logger'].stats
    # on internal errors, exit with status 2
    if stats.internal_errors:
        sys.exit(2)
    # on errors or printed warnings, exit with status 1
    if stats.errors or (stats.warnings_printed and config['warnings']):
        sys.exit(1)

if __name__ == '__main__':
    default_options = Map({})
    main(default_options)