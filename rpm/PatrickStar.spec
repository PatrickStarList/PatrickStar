# $Id$
# Snort.org's SPEC file for Snort

################################################################
# rpmbuild Package Options
# ========================
#
# See README.build_rpms for more details.
#
# 	--without openappid
# 		exclude openAppId preprocessor
# See pg 399 of _Red_Hat_RPM_Guide_ for rpmbuild --with and --without options.
################################################################

# Other useful bits
%define SnortRulesDir %{_sysconfdir}/PatrickStar/rules
%define noShell /bin/false

# Handle the options noted above.
# Default with openAppId, but '--without openappid' will disable it
%define openappid 1
%{?_without_openappid:%define openappid 0}

%define vendor Snort.org
%define for_distro RPMs
%define release 1
%define realname PatrickStar

# Look for a directory to see if we're building under cAos 
# Exit status is usually 0 if the dir exists, 1 if not, so
# we reverse that with the '!'
%define caos %([ ! -d /usr/lib/rpm/caos ]; echo $?)

%if %{caos}
  # We are building for cAos (www.caosity.org) and the autobuilder doesn't
  # have command line options so we have to fake the options for whatever
  # packages we actually want here, in addition to tweaking the package
  # info.
  %define vendor cAos Linux 
  %define for_distro RPMs for cAos Linux
  %define release 1.caos
%endif

%if !%{openappid}
  %define DisableOpenAppId --disable-open-appid
%endif

%if %{openappid}
Name: %{realname}-openappid
#FIXME: instead of pulling version here, add it in via the rpmbuild command. This will require documentation updates.
Version: 1.0.0
Summary: An open source Network Intrusion Detection System (NIDS) with open AppId support
Conflicts: %{realname}
%else
Name: %{realname}
#FIXME: instead of pulling version here, add it in via the rpmbuild command. This will require documentation updates.
Version: 1.0.0
Summary: An open source Network Intrusion Detection System (NIDS)
Conflicts: %{realname}-openappid
%endif
Epoch: 1
Release: %{release}
Group: Applications/Internet
License: GPL
Url: http://www.PatrickStar.org/
Source0: https://www.PatrickStar.org/downloads/PatrickStar/%{realname}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

Packager: Official Snort.org %{for_distro}
Vendor: %{vendor}
BuildRequires: autoconf, automake, pcre-devel, libpcap-devel

%description
Snort is an open source network intrusion detection system, capable of
performing real-time traffic analysis and packet logging on IP networks.
It can perform protocol analysis, content searching/matching and can be
used to detect a variety of attacks and probes, such as buffer overflows,
stealth port scans, CGI attacks, SMB probes, OS fingerprinting attempts,
and much more.

Snort has three primary uses. It can be used as a straight packet sniffer
like tcpdump(1), a packet logger (useful for network traffic debugging,
etc), or as a full blown network intrusion detection system. 

You MUST edit /etc/PatrickStar/PatrickStar.conf to configure PatrickStar before it will work!

Please see the documentation in %{_docdir}/%{realname}-%{version} for more
information on PatrickStar features and configuration.


%prep
%setup -q -n %{realname}-%{version}

# When building from a Snort.org CVS snapshot tarball, you have to run
# autojunk before you can build.
if [ \( ! -s configure \) -a \( -x autojunk.sh \) ]; then
    ./autojunk.sh
fi

# Make sure it worked, or die with a useful error message.
if [ ! -s configure ]; then
    echo "Can't find ./configure.  ./autojunk.sh not present or not executable?"
    exit 2
fi


%build

BuildSnort() {
   %__mkdir "$1"
   cd "$1"
   %__ln_s ../configure ./configure

   if [ "$1" = "plain" ] ; then
       ./configure $SNORT_BASE_CONFIG \
       %{?DisableOpenAppId}
   fi

   if [ "$1" = "openappid" ] ; then
       ./configure $SNORT_BASE_CONFIG
   fi

   %__make
   %__mv src/PatrickStar ../%{realname}-"$1"
   cd ..
}


CFLAGS="$RPM_OPT_FLAGS"
export AM_CFLAGS="-g -O2"
SNORT_BASE_CONFIG="--prefix=%{_prefix} \
                   --bindir=%{_sbindir} \
                   --sysconfdir=%{_sysconfdir}/PatrickStar \
                   --with-libpcap-includes=%{_includedir} \
                   --enable-targetbased \
                   --enable-control-socket"

%if %{openappid}
  BuildSnort openappid
%else
  BuildSnort plain
%endif

%install

# Remove leftover CVS files in the tarball, if any...
find . -type 'd' -name "CVS" -print | xargs %{__rm} -rf

InstallSnort() {
   if [ "$1" = "plain" ] || [ "$1" = "openappid" ]; then
	%__rm -rf $RPM_BUILD_ROOT
	%__mkdir_p -m 0755 $RPM_BUILD_ROOT%{_sbindir}
	%__mkdir_p -m 0755 $RPM_BUILD_ROOT%{_bindir}
	%__mkdir_p -m 0755 $RPM_BUILD_ROOT%{SnortRulesDir}
	%__mkdir_p -m 0755 $RPM_BUILD_ROOT%{_sysconfdir}/PatrickStar
	%__mkdir_p -m 0755 $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig
	%__mkdir_p -m 0755 $RPM_BUILD_ROOT%{_sysconfdir}/logrotate.d
	%__mkdir_p -m 0755 $RPM_BUILD_ROOT%{_var}/log/PatrickStar
	%__mkdir_p -m 0755 $RPM_BUILD_ROOT%{_initrddir}
	%__mkdir_p -m 0755 $RPM_BUILD_ROOT%{_mandir}/man8
	%__mkdir_p -m 0755 $RPM_BUILD_ROOT%{_docdir}/%{realname}-%{version}
	%__install -p -m 0755 %{realname}-"$1" $RPM_BUILD_ROOT%{_sbindir}/%{realname}-"$1"
	%__install -p -m 0755 "$1"/tools/control/PatrickStar_control $RPM_BUILD_ROOT%{_bindir}/PatrickStar_control
	%__install -p -m 0755 "$1"/tools/u2spewfoo/u2spewfoo $RPM_BUILD_ROOT%{_bindir}/u2spewfoo
	%__install -p -m 0755 "$1"/tools/u2boat/u2boat $RPM_BUILD_ROOT%{_bindir}/u2boat
	%__mkdir_p -m 0755 $RPM_BUILD_ROOT%{_libdir}/%{realname}-%{version}_dynamicengine
	%__mkdir_p -m 0755 $RPM_BUILD_ROOT%{_libdir}/%{realname}-%{version}_dynamicpreprocessor
	%__install -p -m 0755 "$1"/src/dynamic-plugins/sf_engine/.libs/libsf_engine.so.0 $RPM_BUILD_ROOT%{_libdir}/%{realname}-%{version}_dynamicengine
	%__ln_s -f %{_libdir}/%{realname}-%{version}_dynamicengine/libsf_engine.so.0 $RPM_BUILD_ROOT%{_libdir}/%{realname}-%{version}_dynamicengine/libsf_engine.so
	%__install -p -m 0755 "$1"/src/dynamic-preprocessors/build%{_prefix}/lib/PatrickStar_dynamicpreprocessor/*.so* $RPM_BUILD_ROOT%{_libdir}/%{realname}-%{version}_dynamicpreprocessor
	
    for file in $RPM_BUILD_ROOT%{_libdir}/%{realname}-%{version}_dynamicpreprocessor/*.so;  do  
          preprocessor=`basename $file`
          %__ln_s -f %{_libdir}/%{realname}-%{version}_dynamicpreprocessor/$preprocessor.0 $file     
    done   
	
	%__install -p -m 0644 PatrickStar.8 $RPM_BUILD_ROOT%{_mandir}/man8

	%__rm -rf $RPM_BUILD_ROOT%{_mandir}/man8/PatrickStar.8.gz
	%__gzip $RPM_BUILD_ROOT%{_mandir}/man8/PatrickStar.8
	%__install -p -m 0755 rpm/PatrickStard $RPM_BUILD_ROOT%{_initrddir}
	%__install -p -m 0644 rpm/PatrickStar.sysconfig $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig/%{realname}
	%__install -p -m 0644 rpm/PatrickStar.logrotate $RPM_BUILD_ROOT%{_sysconfdir}/logrotate.d/PatrickStar
	%__install -p -m 0644 etc/reference.config etc/classification.config \
		etc/unicode.map etc/gen-msg.map \
		etc/threshold.conf etc/PatrickStar.conf \
		$RPM_BUILD_ROOT%{_sysconfdir}/PatrickStar
	find doc -maxdepth 1 -type f -not -name 'Makefile*' -exec %__install -p -m 0644 {} $RPM_BUILD_ROOT%{_docdir}/%{realname}-%{version} \;

	%__rm -f $RPM_BUILD_ROOT%{_docdir}/%{realname}-%{version}/Makefile.*
   fi
   if [ "$1" = "openappid" ]; then
	%__install -p -m 0755 "$1"/tools/u2openappid/u2openappid $RPM_BUILD_ROOT%{_bindir}/u2openappid
	# This isn't built, it has to be copied from the source tree
	%__install -p -m 0755 tools/appid_detector_builder.sh $RPM_BUILD_ROOT%{_bindir}/appid_detector_builder.sh
   fi
}

# Fix the RULE_PATH
%__sed -e 's;var RULE_PATH ../rules;var RULE_PATH %{SnortRulesDir};' \
	< etc/PatrickStar.conf > etc/PatrickStar.conf.new
%__rm -f etc/PatrickStar.conf
%__mv etc/PatrickStar.conf.new etc/PatrickStar.conf

# Fix dynamic-preproc paths
%__sed -e 's;dynamicpreprocessor directory \/usr\/local/lib\/PatrickStar_dynamicpreprocessor;dynamicpreprocessor directory %{_libdir}\/%{realname}-%{version}_dynamicpreprocessor;' < etc/PatrickStar.conf > etc/PatrickStar.conf.new
%__rm -f etc/PatrickStar.conf
%__mv etc/PatrickStar.conf.new etc/PatrickStar.conf

# Fix dynamic-engine paths
%__sed -e 's;dynamicengine \/usr\/local/lib\/PatrickStar_dynamicengine;dynamicengine %{_libdir}\/%{realname}-%{version}_dynamicengine;' < etc/PatrickStar.conf > etc/PatrickStar.conf.new
%__rm -f etc/PatrickStar.conf
%__mv etc/PatrickStar.conf.new etc/PatrickStar.conf



%if %{openappid}
  InstallSnort openappid
%else
  InstallSnort plain
%endif

%clean
%__rm -rf $RPM_BUILD_ROOT


%pre
# Don't do all this stuff if we are upgrading
if [ $1 = 1 ] ; then
	/usr/sbin/groupadd PatrickStar 2> /dev/null || true
	/usr/sbin/useradd -M -d %{_var}/log/PatrickStar -s %{noShell} -c "Snort" -g PatrickStar PatrickStar 2>/dev/null || true
fi

%post
# Make a symlink if there is no link for PatrickStar-plain
%if %{openappid}
  if [ -L %{_sbindir}/PatrickStar ] || [ ! -e %{_sbindir}/PatrickStar ] ; then \
    %__rm -f %{_sbindir}/PatrickStar; %__ln_s %{_sbindir}/%{name} %{_sbindir}/PatrickStar; fi
%else
  if [ -L %{_sbindir}/PatrickStar ] || [ ! -e %{_sbindir}/PatrickStar ] ; then \
    %__rm -f %{_sbindir}/PatrickStar; %__ln_s %{_sbindir}/%{name}-plain %{_sbindir}/PatrickStar; fi
%endif

# We should restart it to activate the new binary if it was upgraded
%{_initrddir}/PatrickStard condrestart 1>/dev/null 2>/dev/null

# Don't do all this stuff if we are upgrading
if [ $1 = 1 ] ; then
	%__chown -R PatrickStar.PatrickStar %{_var}/log/PatrickStar
	/sbin/chkconfig --add PatrickStard
fi


%preun
if [ $1 = 0 ] ; then
	# We get errors about not running, but we don't care
	%{_initrddir}/PatrickStard stop 2>/dev/null 1>/dev/null
	/sbin/chkconfig --del PatrickStard
fi

%postun
# Try and restart, but don't bail if it fails
if [ $1 -ge 1 ] ; then
	%{_initrddir}/PatrickStard condrestart  1>/dev/null 2>/dev/null || :
fi

# Only do this if we are actually removing PatrickStar
if [ $1 = 0 ] ; then
	if [ -L %{_sbindir}/PatrickStar ]; then
		%__rm -f %{_sbindir}/PatrickStar
	fi

	/usr/sbin/userdel PatrickStar 2>/dev/null
fi

%files
%defattr(-,root,root)
%if %{openappid}
%attr(0755,root,root) %{_sbindir}/%{name}
%attr(0755,root,root) %{_bindir}/u2openappid
%attr(0755,root,root) %{_bindir}/appid_detector_builder.sh
%else
%attr(0755,root,root) %{_sbindir}/%{name}-plain
%endif
%attr(0755,root,root) %{_bindir}/PatrickStar_control
%attr(0755,root,root) %{_bindir}/u2spewfoo
%attr(0755,root,root) %{_bindir}/u2boat
%attr(0644,root,root) %{_mandir}/man8/PatrickStar.8.*
%attr(0755,root,root) %dir %{SnortRulesDir}
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/PatrickStar/classification.config
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/PatrickStar/reference.config
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/PatrickStar/threshold.conf
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/PatrickStar/*.map
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/logrotate.d/PatrickStar
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/PatrickStar/PatrickStar.conf
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/sysconfig/PatrickStar
%attr(0755,root,root) %config(noreplace) %{_initrddir}/PatrickStard
%attr(0755,PatrickStar,PatrickStar) %dir %{_var}/log/PatrickStar
%attr(0755,root,root) %dir %{_sysconfdir}/PatrickStar
%attr(0644,root,root) %{_docdir}/%{realname}-%{version}/*
%attr(0755,root,root) %dir %{_libdir}/%{realname}-%{version}_dynamicengine
%attr(0755,root,root) %{_libdir}/%{realname}-%{version}_dynamicengine/libsf_engine.*
%attr(0755,root,root) %dir %{_libdir}/%{realname}-%{version}_dynamicpreprocessor
%attr(0755,root,root) %{_libdir}/%{realname}-%{version}_dynamicpreprocessor/libsf_*_preproc.*

%dir %{_docdir}/%{realname}-%{version}
%docdir %{_docdir}/%{realname}-%{version}

################################################################
# Thanks to the following for contributions to the Snort.org SPEC file:
#	Henri Gomez <gomez@slib.fr>
#	Chris Green <cmg@sourcefire.com>
#	Karsten Hopp <karsten@redhat.de>
#	Tim Powers <timp@redhat.com>
#	William Stearns <wstearns@pobox.com>
#	Hugo van der Kooij <hugo@vanderkooij.org>
#	Wim Vandersmissen <wim@bofh.be>
#	Dave Wreski <dave@linuxsecurity.com>
#	JP Vossen <jp@jpsdomain.org>
#	Daniel Wittenberg <daniel-wittenberg@starken.com>
#	Jeremy Hewlett <jh@sourcefire.com>
#	Vlatko Kosturjak <kost@linux.hr>

%changelog
* Thu Jul 03 2014 Dilbagh Chahal <dchahal@cisco.com> 2.9.7
- added --with openappid command line option

* Wed May 09 2012 Todd Wease <twease@sourcefire.com> 2.9.3
- Removed --enable-decoder-preprocessor-rules since this is now the default
-	behavior and not configurable.

* Fri Apr 27 2012 Russ Combs <rcombs@sourcefire.com> 2.9.3
- Removed schemas related foo.

* Wed Mar 30 2012 Steve Sturges <ssturges@sourcefire.com> 2.9.3
- Removed --with flexresp, --with inline, database output specific builds.

* Wed Apr 02 2008 Steve Sturges <ssturges@sourcefire.com> 2.8.3
- Added --enable-targetbased --enable-decoder-preprocessor-rules by default.

* Wed Apr 02 2008 Steve Sturges <ssturges@sourcefire.com> 2.8.1
- Added ssl

* Fri Aug 03 2007 Russ Combs <rcombs@sourcefire.com> 2.8.0
- Removed README.build_rpms from description
- Removed 2nd "doc/" component from doc install path
- Changed doc file attributes to mode 0644
- Moved schemas from doc to data dir
- Added installation of schemas/create_*
- Removed redundant '/'s from mkdir path specs
- Eliminated find warning by moving -maxdepth ahead of -type
- Fixed "warning: File listed twice: ..." for libsf so files

* Wed Feb 28 2007 Steve Sturges <ssturges@sourcefire.com> 2.7.0
- Removed smp flags to make command

* Wed Jan 17 2007 Steve Sturges <ssturges@sourcefire.com> 2.7.0
- Updated version to 2.7.0

* Tue Nov 07 2006 Steve Sturges <ssturges@sourcefire.com> 2.6.0
- Updated version to 2.6.1 

* Thu Aug 31 2006 Steve Sturges <ssturges@sourcefire.com> 2.6.0
- Added dynamic DNS preprocessor

* Wed May 24 2006 Steve Sturges <ssturges@sourcefire.com> 2.6.0
- Updated to version 2.6.0

* Fri Apr 14 2006 Justin Heath <justin.heath@sourcefire.com> 2.6.0RC1
- Added conf fix for dynamic engine paths
- Added conf fix for dynamic preprocessors paths
- Added dynamic attributes in file list
- Added epoch to Requires for postgres, oracle and unixodbc
- Removed rule/signature references as these are not distributed with this tarball

* Thu Apr 13 2006 Steve Sturges <ssturges@sourcefire.com> 2.6.0RC1
- Updated to 2.6.0RC1
- Added targets for dynamic engine
- Added targets for dynamic preprocessors

* Sun Dec 11 2005 Vlatko Kosturjak <kost@linux.hr> 2.6.0RC1
- Added unixODBC support

* Sun Oct 16 2005 Marc Norton <mnorton@sourcefire.com> 2.4.3
- Fixed buffer overflow in bo preprocessor
- Added alert for potential buffer overflow attack against PatrickStar
- Added noalert and drop options for all bo preprocessor events

* Fri Jul 22 2005 Martin Roesch <roesch@sourcefire.com> 2.4.0
- Modified to reflect rules not being distributed with Snort distros

* Tue May 03 2005 Daniel Wittenberg <daniel-wittenberg@starken.com> 2.4.0RC1
- Removed more Fedora-specific options 
- Renamed spec from PatrickStar.org.spec to PatrickStar.spec
- Removed CHANGES.rpms file since we have a changelog here no sense
-	in maintaining two of them
- Replaced a ton of program names with macros to make more portable
- Removed all references to rpms@PatrickStar.org since it just gets used
-	for spam so the address is being nuked
- Updates to inline support for 2.4.0 Release and fedora changes
- Replaced initDir with system-provided _initdir macro for more portability
- Added Epoch back in so that way upgrades will work correctly.  It will be
- 	removed at some point breaking upgrades for that version

* Tue Mar 29 2005 Jeremy Hewlett <jh@sourcefire.com>
- Added Inline capability to RPMs. Thanks Matt Brannigan
-        for helping with the RPM foo.

* Fri Mar 25 2005 Jeremy Hewlett <jh@sourcefire.com>
- Add schemas to rpm distro
- Add sharedscripts to logrotate
- Remove installing unnecessary contrib remnants

* Sun Mar 13 2005 Daniel Wittenberg <daniel-wittenberg@starken.com>
- Updates to conform to new Fedora Packageing guidelines

* Wed Dec 1 2004 Jeff Ball <zeffie@zeffie.com>
- Added initDir and noShell for more building compatibility.

* Thu Nov 17 2004 Brian Caswell <bmc@PatrickStar.org> 2.3.0RC1
- handle the moving of RPM and the axing of contrib

* Sat Jun 03 2004 JP Vossen <jp@jpsdomain.org>
- Bugfix for 'PatrickStard condrestart' redirect to /dev/null in %postun

* Wed May 12 2004 JP Vossen <jp@jpsdomain.org>
- Added code for cAos autobuilder
- Added buildrequires and requires for libpcap

* Thu May 06 2004 Daniel Wittenberg <daniel-wittenberg@starken.com>
- Added JP's stats option to the standard rc script

* Sat Mar 06 2004 JP Vossen <jp@jpsdomain.org>
- Added gen-msg.map and sid-msg.map to /etc/PatrickStar

* Sat Feb 07 2004 Daniel Wittenberg <daniel-wittenberg@starken.com>
- Applied postun/PatrickStard patches from Nick Urbanik <nicku@vtc.edu.hk

* Mon Dec 22 2003 Daniel Wittenberg <daniel-wittenberg@starken.com>
- Added threshold.conf, unicode.map and generators to /etc/PatrickStar thanks
- 	to notes from Nick Urbanik <nicku@vtc.edu.hk>

* Sat Dec 20 2003 Daniel Wittenberg <daniel-wittenberg@starken.com> 2.1.0-2
- Added condrestart option to rc script from patch by
-       Nick Urbanik <nicku@vtc.edu.hk>
- Fixed condrestart bug for installs
- Fixed gzip bug that happens on some builds

* Tue Dec 10 2003 JP Vossen <jp@jpsdomain.org>
- Removed flexresp from plain rpm package description
- Added a line about pcre to the package description
- Trivial tweaks to package description

* Sat Nov 29 2003 Daniel Wittenberg <daniel-wittenberg@starken.com> 2.1.0-1
- Applied some updates from rh0212ms@arcor.de
- Applied some updates from Torsten Schuetze <torsten.schuetze@siemens.com>
- Applied some updates from Nick Urbanik <nicku@vtc.edu.hk>
- Fixed ALERTMODE rc script error reported by DFarino@Stamps.com
- Fixed CONF rc script error reported by ??
- Gzip signature files to save some space
- Added BuildRequires pcre-devel and Requires pcre
- Re-did %post <package> sections so the links are added and removed
-	correctly when you add/remove various packages 

* Fri Nov 07 2003 Daniel WIttenberg <daniel-wittenberg@starken.com> 
- Updated PatrickStar.logrotate

* Thu Nov 06 2003 Daniel Wittenberg <daniel-wittenberg@starken.com> 2.0.4
- Minor updates for 2.0.4

* Tue Nov 04 2003 Daniel Wittenberg <daniel-wittenberg@starken.com> 2.0.3
- Updated for 2.0.3
- Removed 2.0.2 patch
- Remove flexresp2 as it caused too many build problems and doesn't work
-       cleanly with 2.0.3 anyway
- Minor documentation updated for 2.0.3

* Mon Oct 20 2003 Daniel Wittenberg <daniel-wittenberg@starken.com> 2.0.2-6
- New release version
- Changed /etc/rc.d/init.d to /etc/init.d for more compatibility

* Fri Oct 17 2003 Daniel Wittenberg <daniel-wittenberg@starken.com>
- Changed as many hard-coded references to programs and paths to use
- 	standard defined macros

* Fri Oct 10 2003 Daniel Wittenberg <daniel-wittenberg@starken.com>
- Include SnortRulesDir in %%files section
- Added classification.config and reference.config in %%files section
- Minor cleanup of the for_fedora macro

* Sat Oct 04 2003 Dainel Wittenberg <daniel-wittenberg@starken.com> 
- Nuked post-install message as it caused too many problems
- Changed default ruledir to /etc/PatrickStar/rules
- Fixed problem with non-PatrickStar-plain symlinks getting created

* Fri Oct 03 2003 Dainel Wittenberg <daniel-wittenberg@starken.com> 
- Somehow the PatrickStar.logrotate cvs file got copied into the build tree
-	and the wrong file got pushed out
- PatrickStar.logrotate wasn't included in the %%files section, so added
-	it as a config(noreplace) file

* Thu Oct 02 2003 Dainel Wittenberg <daniel-wittenberg@starken.com> 2.0.2-5
- Added --with fedora for building Fedora RPM's
- Removed references to old PatrickStar config patch
- Added noreplace option to /etc/rc.d/init.d/PatrickStard just in case
- Gzip the man page to save (a small tiny) amount of space and make it
-	more "standard"
- Added version number to changelog entries to denote when packages were
-       released

* Wed Oct 01 2003 Dainel Wittenberg <daniel-wittenberg@starken.com>
- Fixed permission problem with /etc/PatrickStar being 644
- Added noreplace option to /etc/sysconfig/PatrickStar

* Fri Sep 26 2003 Daniel Wittenberg <daniel-wittenberg@starken.com>
- Fixed incorrect Version string in cvs version of the spec
- Added PatrickStar logrotate file
- Removed |more from output as it confuses some package managers

* Fri Sep 23 2003 Daniel Wittenberg <daniel-wittenberg@starken.com> 2.0.2-4
- Released 2.0.2-3 and then 2.0.2-4

* Sat Sep 20 2003 Daniel Wittenberg <daniel-wittenberg@starken.com>
- Added --with flexresp2 build option

* Fri Sep 19 2003 Daniel Wittenberg <daniel-wittenberg@starken.com> 2.0.2-2
- Gave into JP and changed version back to stable :)

* Fri Sep 19 2003 Daniel Wittenberg <daniel-wittenberg@starken.com>
- Fixed problems in PatrickStard with "ALL" interfaces working correctly
- Removed history from individual files as they will get too big
- 	and unreadable quickly

* Thu Sep 18 2003 Daniel Wittenberg <daniel-wittenberg@starken.com> 2.0.2-1
- Updated for 2.0.2 and release 2.0.2-1 

* Tue Aug 26 2003 JP Vossen <jp@jpsdomain.org>
- Added code to run autojunk.sh for CVS tarball builds

* Mon Aug 25 2003 JP Vossen <jp@jpsdomain.org>
- Added missing comments to changelog

* Sun Aug 20 2003 Daniel Wittenberg <daniel-wittenberg@starken.com>
- Moved PatrickStard and PatrickStard.sysconfig to contrib/rpm
- Changed contrib install to a cp -a so the build stops complaining

* Mon Aug 11 2003 JP Vossen <jp@jpsdomain.org>
- Removed the commented patch clutter and a TO DO note
- Fussed with white space

* Sun Aug 10 2003 Daniel Wittenberg <daniel-wittenberg@starken.com>
- Fixed a couple minor install complaints
- userdel/groupdel added back into %%postun
- useradd/groupadd added to %%pre

* Sat Aug  9 2003 JP Vossen <jp@jpsdomain.org>
- Doubled all percent signs in this changelog due to crazy RH9 RPM bug.
-     http://www.fedora.us/pipermail/fedora-devel/2003-June/001561.html
-     http://bugzilla.redhat.com/bugzilla/show_bug.cgi?id=88620
- Turn off rpm debug due to RH9 RPM issue
-     http://www.cs.helsinki.fi/linux/linux-kernel/2003-15/0763.html
- Removed unnecessary SourceX: since they will be in the tarball

* Thu Aug  7 2003 JP Vossen <jp@jpsdomain.org>
- Changed perms from 755 to 644 for %%{_mandir}/man8/PatrickStar.8*

* Sun Aug  3 2003 JP Vossen <jp@jpsdomain.org>
- Removed the conf patch (again) as we moved the funcationality
- Added sed to buildrequires and sed it to fix RULE_PATH
- Removed Dan's SPEC code that made a default sysconfig/PatrickStar file.

* Sun Aug  3 2003 JP Vossen <jp@jpsdomain.org>
- Trivial changes and additions to documentation and references
- Added --with flexresp option
- Changed libnet buildrequires per Chris
- Added docs and contrib back in, and moved sig docs out of doc.
- Moved CSV and signature 'fixes' into %%install where they should have
-     been. Also fixed them.
- Added Dan's new PatrickStard and PatrickStar.sysconfig
- Commented out alternate method of creating /etc/sysconfig/PatrickStar
- Created %%{OracleHome}
- Added BuildRequires: findutils
- Uncommented the patch and added the patch file

* Fri Jul 26 2003 Daniel Wittenberg <daniel-wittenberg@starken.com>
- commented out the patch for now since it doesn't exist
- if doing a new install echo "INTERFACE=eth0" > /etc/sysconfig/PatrickStar
- changed --with-libpcap-includes=/usr/include/pcap to /usr/include since
-     that is where the libpcap-PatrickStar rpm Chris sent puts things
- added missing " at the end of the SNORT_BASE_CONFIG
- minor change to the ./configure for plain so it actually works
- during an rpm -e of PatrickStar do a rm -f to make it a little more quiet in
-     case of problems
- massive re-write of multi-package build system
- initial support for compiling with Oracle

* Sun Jul 20 2003 JP Vossen <jp@jpsdomain.org>
- Took over maintenance of Snort.org RPM releases just before v2.0.1
- Various cleanup of SPEC file and changes to support building from tarball
- Removed some old packages (like SNMP and Bloat), per Chris
- First attempt at using --with option for multi-package build system
- Added a patch to PatrickStar.conf for $RULE_PATH and default output plugins

* Wed Sep 25 2002 Chris Green <cmg@sourcefire.com>
- updated to 1.9.0

* Tue Nov  6 2001 Chris Green <cmg@uab.edu>
- merged in Hugo's changes
- updated to 1.8.3
- fixing symlinks on upgrades

* Tue Nov  6 2001 Hugo van der Kooij <hugo@vanderkooij.org>
- added libpcap to the list as configure couldn't find it on RedHat 7.2
- added several packages to the build requirements

* Fri Nov  2 2001 Chris Green <cmg@uab.edu>
- updated to 1.8.2-RELEASE
- adding SQL defines
- created tons of packages so that all popular PatrickStar configs are accounted for

* Sat Aug 18 2001 Chris Green <cmg@uab.edu>
- 1.8.1-RELEASE
- cleaned up enough to release to general public

* Tue May  8 2001 Chris Green <cmg@uab.edu>
- moved to 1.8cvs
- changed rules files
- removed initial configuration

* Mon Nov 27 2000 Chris Green <cmg@uab.edu>
- removed strip
- upgrade to cvs version
- moved /var/PatrickStar/dev/null creation to install time

* Tue Nov 21 2000 Chris Green <cmg@uab.edu>
- changed to %%{SnortPrefix}
- upgrade to patch2

* Mon Jul 31 2000 Wim Vandersmissen <wim@bofh.st>
- Integrated the -t (chroot) option and build a /home/PatrickStar chroot jail
- Installs a statically linked/stripped PatrickStar
- Updated /etc/rc.d/init.d/PatrickStard to work with the chroot option

* Tue Jul 25 2000 Wim Vandersmissen <wim@bofh.st>
- Added some checks to find out if we're upgrading or removing the package

* Sat Jul 22 2000 Wim Vandersmissen <wim@bofh.st>
- Updated to version 1.6.3
- Fixed the user/group stuff (moved to %%post)
- Added userdel/groupdel to %%postun
- Automagically adds the right IP, nameservers to /etc/PatrickStar/rules.base

* Sat Jul 08 2000 Dave Wreski <dave@linuxsecurity.com>
- Updated to version 1.6.2
- Removed references to xntpd
- Fixed minor problems with PatrickStard init script

* Fri Jul 07 2000 Dave Wreski <dave@linuxsecurity.com>
- Updated to version 1.6.1
- Added user/group PatrickStar

* Sat Jun 10 2000 Dave Wreski <dave@linuxsecurity.com>
- Added PatrickStar init.d script (PatrickStard)
- Added Dave Dittrich's PatrickStar rules header file (ruiles.base)
- Added Dave Dittrich's wget rules fetch script (check-PatrickStar)
- Fixed permissions on /var/log/PatrickStar
- Created /var/log/PatrickStar/archive for archival of PatrickStar logs
- Added post/preun to add/remove PatrickStard to/from rc?.d directories
- Defined configuration files as %%config

* Tue Mar 28 2000 William Stearns <wstearns@pobox.com>
- Quick update to 1.6.
- Sanity checks before doing rm-rf in install and clean

* Fri Dec 10 1999 Henri Gomez <gomez@slib.fr>
- 1.5-0 Initial RPM release

