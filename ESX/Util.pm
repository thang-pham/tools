#!/usr/bin/perl
#
# Utility library for managing ESXi.
#   To import this library, just add "use ESX::Util;" to your Perl script.
#
# @author: Thang Pham <thang.g.pham@gmail.com>

package ESX::Util;

our ($VERSION, @ISA, @EXPORT);
BEGIN {
    $VERSION = "0.10";  # Module version

    require Exporter;
    @ISA = qw(Exporter);
    
    # By exporting each method listed here, you do not have to specify the
    # package name to use each function, i.e. ESX::Util->foobar().  Instead,
    # after the module is imported, the method name can be directly used,
    # i.e. foobar().
    @EXPORT = qw(
        addHostToDatacenter
        addHostToDatacenter
        addPortGroup
        createCluster
        createDatacenter
        destroyVMByName
        endVcenterSession
        findSuitableDatastore
        generateSslThumbprint
        getDeviceByLabel
        getEsxCertificate
        getHostInClusterByName
        getHostInDatacenterByName
        getHostIp
        getHostMac
        getHostView
        getLogger
        getMgtIP
        getMgtMac
        getOvfToolVersion
        getSshSession
        getVMByName
        getVSwitchVLANs
        isIPv4
        isToolsOk
        powerOnVM
        readConfig
        reconfigVM
        runOvftool
        setupEsxiNetwork
        startVcenterSession
        unregisterHostByName
        updatePortGroup
        waitOnTask
    );
}

use strict;
use warnings;

use Data::Dumper;
use Digest::SHA qw(sha1_hex);
use Fcntl qw(:flock SEEK_END); # import LOCK_* and SEEK_END constants
use File::Temp;
use Log::Log4perl;
use MIME::Base64 qw(decode_base64);
use Net::OpenSSH;
use NetAddr::IP;
use VMware::VILib;
use VMware::VIRuntime;


###############################################################################
# Utility methods
###############################################################################

# Establish a vCenter or ESX host session
sub startVcenterSession {
    my ($vcenterIp, $vcenterUser, $vcenterPassword) = @_;

    my $serviceUrl = Vim->new(server => $vcenterIp)->get_service_url();
    my $session = Util::connect($serviceUrl, $vcenterUser, $vcenterPassword);
    return $session;
}

# Destroys a vCenter or ESX host session
sub endVcenterSession {
    my ($session) = @_;
    Util::disconnect($session);
}

# Returns the ovftool version
sub getOvfToolVersion {
    my $out = qx(ovftool -v);
    chomp($out);
    
    # NOTE: ovftool 3.5.x is not supported on vCenter 6.x, i.e. segmentation fault.
    my ($toolVersion, $buildVersion) = $out =~ /VMware ovftool (.*) \((.*)\)/;
    return $toolVersion;
}

# Executes an ovftool command
sub runOvftool {
    my (@ovftoolCmd) = @_;
    my $logger = getLogger();
    $logger->info("Running ovftool: ", join ' ', @ovftoolCmd);

    my $deployOk = 0;
    my $tries = 0;

    # There are often connection problems using ovftool.  Retry if there is
    # a bad connection.
    while ($tries < 3) {
        my @output = qx( @ovftoolCmd 2>&1 );
        my $foundResult = 0;
        my $badConnection = 0;
        foreach my $line (@output) {
            chomp $line;
            $line =~ s/^\s+//;
            $line =~ s/\s+$//;

            if ($line =~ /^RESULT/) {
                $foundResult = 1;
                next;
            } if ($foundResult && $line =~ /^\+ SUCCESS/) {
                $deployOk = 1;
                last;
            } if ($line =~ /Couldn&apos;t connect to server/) {
                $badConnection = 1;
            } if ($line =~ /ovftool.io.file.not.found/) {
                $badConnection = 1;
            }
        }

        # Only retry on a bad connection
        if ($badConnection == 1) {
            $tries++;
        } else {
            last;
        }
    }

    unless ($deployOk) {
        return 9;
    }
    return 0;
}

# Establish an SSH session to a given host
sub getSshSession {
    my ($host, $user, $passwd, $knownHosts) = @_;
    my $ssh = Net::OpenSSH->new($host, user => $user, password => $passwd,
                                master_opts => [-o => "StrictHostKeyChecking=no",
                                                -o => "UserKnownHostsFile=$knownHosts"]);
    if ($ssh->error) {
        print "ERROR: Failed to establish SSH connection to $host: " . $ssh->error . "\n";
        exit 9;
    } else {
        return $ssh;
    }
}

# Wait on a given task
sub waitOnTask {
    # For more info, see http://www.virtuin.com/2012/11/automate-adding-esxi-hosts-to-vcenter.html
    my ($session, $taskRef, $message) = @_;
    my $logger = getLogger();

    my $taskView = $session->get_view(mo_ref => $taskRef);
    my $taskInfo = $taskView->info->state->val;
    while (1) {
        my $info = $taskView->info;
        if ($info->state->val eq 'success') {
            $logger->info($message);  # If task was successful, then log the given message
            return $info->result;
            last;
        } elsif ($info->state->val eq 'error') {
            my $soapFault = SoapFault->new;
            $soapFault->name($info->error->fault);
            $soapFault->detail($info->error->fault);
            $soapFault->fault_string($info->error->localizedMessage);
            die "$soapFault\n";
        }

        sleep 5;
        $taskView->ViewBase::update_view_data();
    }
}

# Get the ESX host certificate (to add a host to vCenter)
sub getEsxCertificate {
    # For more info, see http://www.virtuin.com/2012/11/automate-adding-esxi-hosts-to-vcenter.html
    my (%args) = @_;

    my ($esxHost, $esxUser, $esxPass, $esxPort, $ua, $res, $certificate, $realmName);
    $esxHost = $args{esx_host};
    $esxUser = $args{esx_user};
    $esxPass = $args{esx_pass};
    $esxPort = "443";

    $certificate = undef;
    $ua = LWP::UserAgent->new();
    if ($LWP::UserAgent::VERSION >= 6) {
        $ua->ssl_opts('verify_hostname' => 0);
        $ua->ssl_opts('SSL_verify_mode' => 0);
    }
    $realmName = "VMware HTTP server";
    $ua->credentials( "$esxHost:$esxPort", $realmName, $esxUser => $esxPass );
    $res = $ua->get("https://$esxHost:$esxPort/host/ssl_cert");

    die $res->status_line unless $res->is_success;
    $certificate = $res->decoded_content();

    return $certificate;
}

# Get the SSL thumbprint (to add a host to vCenter)
sub generateSslThumbprint {
    my (%args) = @_;

    my ($pem, $der, $digest, $sslThumbprint);
    $pem = delete($args{pem});

    # Strip PEM tags to get Base64 encoded certificate data
    $pem =~ s/-{1,}(BEGIN|END) CERTIFICATE-{1,}//g;

    # Convert PEM to DER (decode Base64)
    $der = decode_base64($pem);

    # Generate SHA1 hex digest
    $digest = sha1_hex($der);

    # Format thumbprint
    $sslThumbprint = "";
    for (my $i=0; $i < length($digest); $i+=2) {
        my $substring = substr($digest, $i, 2);
        $sslThumbprint .= uc($substring);
        unless ($i >= 38) {
            $sslThumbprint .= ":";
        }
    }

    return $sslThumbprint;
}

# Checks if a given address is IPv4
sub isIPv4 {
    my ($address) = @_;

    my $ipv4 = $address =~ /^\d+\.\d+\.\d+\.\d+$/;
    unless ($ipv4) {
        return 0;
    }

    # Check that bytes are in range
    for (split /\./, $ipv4) {
        return 0 if $_ < 0 or $_ > 255;
    }

    return 1;
}

# Returns a VM object with the given name
sub getVMByName {
    my ($session, $name) = @_;
    my $vms = $session->find_entity_views(view_type => 'VirtualMachine',
                                          filter => {'name' => $name});

    # There should only be one vhost of the given name
    if (@{$vms} != 1) {
        return undef;
    }

    return @{$vms}[0];
}

# Returns a ComputeResource object (ESX host) in a datacenter with the given name
sub getHostInDatacenterByName {
    my ($session, $name) = @_;
    my $hosts = $session->find_entity_views(view_type => "ComputeResource", filter => {'name' => $name});

    # There should only be one vhost of the given name
    if (@{$hosts} != 1) {
        return undef;
    }

    return @{$hosts}[0];
}

# Returns a HostSystem object in a cluster with the given name
sub getHostInClusterByName {
    my ($session, $hostname, $cluster) = @_;
    my $clusterView = $session->find_entity_view(view_type => "ClusterComputeResource", filter => {'name' => $cluster});

    my $hosts;
    if ($clusterView) {
        $hosts = $session->find_entity_views(view_type => 'HostSystem',
                                             begin_entity => $clusterView,
                                             filter => {'name' => $hostname});
    }

    # There should only be one vhost of the given name
    unless (defined $hosts && @{$hosts} == 1) {
        return undef;
    }

    return @{$hosts}[0];
}

# Turns on a VM
sub powerOnVM {
    my ($session, $vm) = @_;

    my $task = $vm->PowerOnVM_Task();
    waitOnTask($session, $task, "VM ".$vm->name." was powered on.");
}

# Returns a VM device with the given label, e.g. Network adapter 2
sub getDeviceByLabel {
    my ($searchLabel, $devices) = @_;

    my $device = undef;
    my $label = undef;

    foreach $device (@$devices) {
        $label = $device->deviceInfo->label;

        if ($searchLabel eq $label) {
            return $device;
        }
  }

  return undef;
}

# Destorys a VM
sub destroyVMByName {
    my ($session, $name) = @_;
    my $logger = getLogger();

    my $vhost = getVMByName($session, $name);
    if ($vhost) {
        eval {
            my $task = $vhost->PowerOffVM_Task();
            waitOnTask($session, $task, "$name powered off.");
        };
        if ( $@ ) {
            $logger->warn("Power off of $name reported: $@");
        }
        eval {
            my $task = $vhost->Destroy_Task();
            waitOnTask($session, $task, "$name destroyed.");
        };
        if ( $@ ) {
            $logger->warn("Destroy of $name reported: $@");
        }
    }
}

# Returns a logger
sub getLogger {
    unless (Log::Log4perl->initialized()) {
        unless (defined $ENV{ESXUTILLOGFILE}) {
           $ENV{ESXUTILLOGFILE} = "/var/log/esx-util.log";
        }

        # Initialize logger
        my $logConf = q(
           log4perl.rootLogger              = DEBUG, LOG1
           log4perl.appender.LOG1           = Log::Log4perl::Appender::File
           log4perl.appender.LOG1.filename  = sub { $ENV{ESXUTILLOGFILE} };
           log4perl.appender.LOG1.mode      = append
           log4perl.appender.LOG1.layout    = Log::Log4perl::Layout::PatternLayout
           log4perl.appender.LOG1.layout.ConversionPattern = %P %d %p %m%n
        );
        Log::Log4perl::init(\$logConf);
    }

    return Log::Log4perl->get_logger();
}

# Reads in a file, containing newline separated key/value pairs, e.g.
#   key1 = value1
#   key2 = value2
#   key3 = value3
sub readConfig {
    my ($configPath, $config) = @_;
    my $logger = getLogger();

    unless (-e $configPath) {
        print "ERROR: Cannot find $configPath.\n";
        return;
    }

    open(my $fh, $configPath);

    $logger->info("Reading config file at $configPath.");
    while (<$fh>) {
        chomp;     # No newline
        s/#.*//;   # No comments
        s/^\s+//;  # No leading white
        s/\s+$//;  # No trailing white
        next unless length;
        my ($var, $value) = split(/\s*=\s*/, $_, 2);
        $config->{$var} = $value;  # Save as environment variables
    }
    close $fh;
}

# Checks if VMware Tools is installed and running on a VM
sub isToolsOk {
    my ($session, $name, $noExit) = @_;
    my $logger = getLogger();

    my $vm = getVMByName($session, $name);
    unless (defined $vm) {
        $logger->error("Failed to find vm $name.");
        if ($noExit) {
            return undef;
        }
        print "ERROR: Could not find virtual machine - $name.";
        exit 9;
    }

    # Check if the vhost is powered on
    my $powerStat = $vm->runtime->powerState->val;
    my $attempts = 0;
    my $maxAttempts = 12;
    if ($noExit) {
        $maxAttempts = 2;
    }
    while ($attempts < $maxAttempts && $powerStat ne "poweredOn") {
        sleep 5;
        $vm = getVMByName($session, $name);
        if (defined $vm) {
            $powerStat = $vm->runtime->powerState->val;
        } else {
            my $msg = "Failed to find power for vm $name.";
            $logger->error($msg);
            if ($noExit) {
                return undef;
            }
            print "ERROR: $msg\n";
            exit 9;
        }
        $logger->info("Power status on $name is $powerStat.");
        $attempts++;
    }
    unless ($powerStat eq "poweredOn") {
        $logger->error("No power: $powerStat for ".$vm->name.".");
        if ($noExit) {
            return undef;
        }
        print "ERROR: Cannot find IP of " . $vm->name . ".  No power: $powerStat.\n";
        exit 9;
    }

    # Check if VMware Tools are installed on the vhost
    my $toolsStat = $vm->guest->toolsStatus->val;
    $attempts = 0;
    $maxAttempts = 36;
    if ($noExit) {
        $maxAttempts = 2;
    }
    while ($attempts < $maxAttempts && $toolsStat ne "toolsOk") {
        sleep 5;
        $vm = getVMByName($session, $name);
        $toolsStat = $vm->guest->toolsStatus->val;
        $logger->info("VMware Tools status on $name is $toolsStat.");
        $attempts++;
    }

    unless (defined $vm->guest->toolsStatus && $toolsStat eq "toolsOk") {
        $logger->error("No tools (power: $powerStat) for ".$vm->name.".");
        if ($noExit) {
            return undef;
        }
        print "ERROR: Cannot find IP of " . $vm->name . ".  No tools (power: $powerStat).\n";
        exit 9;
    }
    return $vm;
}

# Returns the VM IP address
sub getHostIp {
    my ($session, $name) = @_;
    my $logger = getLogger();

    my $vm = isToolsOk(@_);
    unless ($vm) {
        return undef;
    }

    # Get IPv4 address
    my $ip = getMgtIP($vm);
    my $attempts = 0;
    while ($attempts < 10 && !defined $ip) {
        sleep 5;
        $vm = getVMByName($session, $name);
        $ip = getMgtIP($vm);
        if (defined $ip) {
            $logger->info("$name mgt IPv4 is $ip.");
        } else {
            $logger->info("No mgt IPv4 found for $name.");
        }
        $attempts++;
    }

    unless (defined $ip) {
        my $msg = "IPv4 address is missing on " . $vm->name . ".  Tools status is " . $vm->guest->toolsStatus->val . " .  Power state is " . $vm->runtime->powerState->val . ".";
        $logger->error($msg);
        print "ERROR: $msg\n";
        exit 9;
    }
    return $ip;
}

# Returns the VM MAC address
sub getHostMac {
    my ($session, $name) = @_;
    my $logger = getLogger();

    my $vm = isToolsOk(@_);
    unless ($vm) {
        return undef;
    }

    # Get mac address
    my $mac = getMgtMac($vm);
    my $attempts = 0;
    while ($attempts < 20 && !defined $mac) {
        sleep 5;
        $vm = getVMByName($session, $name);
        $mac = getMgtMac($vm);
        if (defined $mac) {
            $logger->info("$name MAC is $mac.");
        } else {
            $logger->info("No MAC found for $name.");
        }
        $attempts++;
    }
    unless (defined $mac) {
        my $msg = "MAC address is missing on " . $vm->name . ".  Tools status is " . $vm->guest->toolsStatus->val . ".  Power state is " . $vm->runtime->powerState->val . ".";
        $logger->error($msg);
        print "ERROR: $msg\n";
        exit 9;
    }
    return $mac;
}

# Returns the management IP address (i.e. on VM Network)
sub getMgtIP {
    my $vm = shift;

    my $logger = getLogger();
    my $vmGuest = $vm->guest;

    if ($vmGuest) {
        my $vmGuestNet = $vmGuest->net;
        if (defined $vmGuestNet) {
            for my $guestNicInfo (@$vmGuestNet) {
                my $guestNetwork = $guestNicInfo->network;
                if ( (defined $guestNetwork && $guestNetwork eq 'VM Network') ||
                     ($#{$vmGuestNet} == 0) ) {
                    my $guestIpAddress = $guestNicInfo->ipAddress;
                    for my $ip (@$guestIpAddress) {
                        if (isIPv4($ip)) {
                            $logger->info($vm->name." IPv4 is $ip.");
                            return $ip;
                        }
                    }
                }
            }
        }

        my $ip = $vmGuest->ipAddress;
        if (defined $ip && ref $ip ne 'ARRAY') {
            if (isIPv4($ip)) {
                $logger->info($vm->name." IPv4 is $ip.");
                return $ip;
            }
        }
    }

    my $vmSummary = $vm->summary;
    if (defined $vmSummary) {
        my $vmGuest = $vmSummary->guest;
        if (defined $vmGuest) {
            return $vmGuest->ipAddress;
        }
    }

    return undef;
}

# Returns the management MAC address (i.e. on VM Network)
sub getMgtMac {
    my $vm = shift;

    my $logger = getLogger();
    my $vmGuest = $vm->guest;

    if ($vmGuest) {
        my $vmGuestNet = $vmGuest->net;
        if (defined $vmGuestNet) {
            for my $guestNicInfo (@$vmGuestNet) {
                my $guestNetwork = $guestNicInfo->network;
                if ( (defined $guestNetwork && $guestNetwork eq 'VM Network') ||
                     ($#{$vmGuestNet} == 0) ) {
                    my $guestMacAddress = $guestNicInfo->macAddress;
                    $logger->info($vm->name." mac is $guestMacAddress.");
                    return $guestMacAddress;
                }
            }
        }
    }

    return undef;
}

# Returns the HostSystem view
sub getHostView {
    my ($session, $esxOnly, $host) = @_;
    my $logger = getLogger();

    my $hostView;
    if ( $esxOnly ) {
        # If you are not using a vCenter session, but instead an ESX session
        my $hostViews = $session->find_entity_views(view_type => 'HostSystem');
        my $hostCount = @$hostViews;
        if ( $hostCount == 1) {
            $hostView = $hostViews->[$[];
        } else {
            $logger->warn("Did not expect to find more then 1 host");
            # Do the filter listed in the else below.  Saves time
            # to not redo the Vim::find_entity_view
            for my $tmpHost (@$hostViews) {
                if ($tmpHost->name eq $host) {
                    $hostView = $tmpHost;
                    last;
                }
            }
        }
    } else {
        $hostView = $session->find_entity_view(view_type => 'HostSystem',
                                               filter => {name => $host });
    }
    unless ( defined($hostView) ) {
        print "ERROR: Failed to find $host.\n";
        exit 9;
    }
    return $hostView;
}

# Removes an ESX host from inventory
sub unregisterHostByName {
    my ($session, $name, $clusterName) = @_;
    my $logger = getLogger();

    my $vhost;
    if ($clusterName ne "") {
        $vhost = getHostInClusterByName($session, $name, $clusterName);

        # Enter host into maintenance mode
        eval {
            my $task = $vhost->EnterMaintenanceMode_Task(timeout => 0, evacuatePoweredOffVms => 'false');
            waitOnTask($session, $task, "$name entered maintenance mode.");
        };
        if ( $@ ) {
            $logger->warn("Set maintenance mode of $name reported: $@");
        }
    } else {
        $vhost = getHostInDatacenterByName($session, $name);
    }

    if ($vhost) {
        # A standalone HostSystem can be destroyed only by invoking destroy
        # on its parent ComputeResource
        eval {
            my $task = $vhost->Destroy_Task();
            waitOnTask($session, $task, "$name destroyed.");
        };
        if ( $@ ) {
            $logger->warn("Destroy of $name reported: $@");
        }
    }
}

# Returns the VLAN on a given vSwitch and port group
sub getVSwitchVLANs {
    my ($session, $host, $vSwitchName, $portGroup) = @_;
    my $logger = getLogger();

    my $hostView = getHostView($session, 0, $host);
    my $networkView = $session->get_view(mo_ref => $hostView->configManager->networkSystem);
    my $portGroups = $networkView->networkConfig->portgroup;
    foreach (@$portGroups) {
        if (defined($_->spec)) {
            if ($_->spec->vswitchName eq $vSwitchName && $_->spec->name eq $portGroup) {
                return $_->spec->vlanId;
            }
        }
    }

    return undef;
}

# Returns a datastore that has at least the given free space
sub findSuitableDatastore {
    my $session = shift;
    my $host = shift;
    my $freeSpace = shift;  # Size in M

    my $hostView = getHostView($session, 0, $host);
    my $datastores = $session->get_views(mo_ref_array => $hostView->datastore);
    foreach (@$datastores) {
        if ($_->summary->type eq 'NFS' && int($_->summary->freeSpace)/(1024*1024*1024) > $freeSpace) {
            return $_->summary->name;
            last;
        }
    }

    return undef;
}

# Reconfigures a VM
sub reconfigVM {
    my $session = shift;
    my $vm = shift;  # VirtualMachine object
    my $memory = shift;  # Size in MB
    my $diskLabel = shift;  # Disk label to resize
    my $diskSize = shift;  # Size in KB
    my $nicType = shift;
    my $reflectHost = shift;  # Inherit the same hardware profile as the underlying host
    
    my $logger = getLogger();

    # Figure out the VM disk capacity
    my $devices = $vm->config->hardware->device;
    my $rootDisk = getDeviceByLabel($diskLabel, $devices);
    unless (defined $rootDisk) {
        my $msg = "Could not find disk by label - $diskLabel";
        $logger->error($msg);
        print "ERROR: $msg\n";
    }

    my @deviceChanges;
    my $newDevice = VirtualDisk->new(deviceInfo    => $rootDisk->deviceInfo,
                                     key           => $rootDisk->key,
                                     controllerKey => $rootDisk->controllerKey,
                                     unitNumber    => $rootDisk->unitNumber,
                                     deviceInfo    => $rootDisk->deviceInfo,
                                     backing       => $rootDisk->backing,
                                     capacityInKB  => $diskSize);  # Size must be in KB
    push @deviceChanges, VirtualDeviceConfigSpec->new(device    => $newDevice,
                                                      operation =>  VirtualDeviceConfigSpecOperation->new('edit'));
    
    my $msg = "$diskLabel was resized to $diskSize" . "K.";

    # Delete old network adapter (VMXNET3) on vhost_pg and replace with
    # a new network adapter on vhost_pg.
    my $nicLabel = "Network adapter 2";
    my $vhostPgNic = getDeviceByLabel($nicLabel, $devices);
    if (defined $vhostPgNic) {
        my $backingInfo = VirtualEthernetCardNetworkBackingInfo->new(deviceName => "vhost_pg");
        my %nicConfig = (key => -1,
                         backing => $backingInfo,
                         addressType => 'Generated');
        my $newNetworkDevice = undef;
        if ($nicType eq 'e1000') {
           $newNetworkDevice = VirtualE1000->new(%nicConfig);
        } elsif ($nicType eq 'e1000e') {
            $newNetworkDevice = VirtualE1000e->new(%nicConfig);
        } elsif ($nicType eq 'vmxnet3') {
            $newNetworkDevice = VirtualVmxnet3->new(%nicConfig);
        } elsif ($nicType eq 'pcnet32') {
            $newNetworkDevice = VirtualPCNet32->new(%nicConfig);
        } elsif ($nicType eq 'vmxnet2') {
           $newNetworkDevice = VirtualVmxnet2->new(%nicConfig);
        } elsif ($nicType eq 'vmxnet') {
           $newNetworkDevice = VirtualVmxnet->new(%nicConfig);
        } else {
           my $msg = "$nicType is not a recognized type of network adapter. Using default 'vmxnet3'.\n";
           $logger->warn($msg);
           print "WARN: $msg\n";
        }

        if (defined $newNetworkDevice) {
            push @deviceChanges, VirtualDeviceConfigSpec->new(device    => $vhostPgNic,
                                                              operation =>  VirtualDeviceConfigSpecOperation->new('remove'));
            push @deviceChanges, VirtualDeviceConfigSpec->new(device    => $newNetworkDevice,
                                                              operation =>  VirtualDeviceConfigSpecOperation->new('add'));
            $msg .= " Network adapter type was set to $nicType.";
        }
    }

    my %specArgs;
    $specArgs{deviceChange} = \@deviceChanges;

    # Resize the VM memory (if needed)
    if (defined $memory && $memory > 0) {
        $specArgs{memoryMB} = $memory;
        $msg .= " Memory was resized to $memory" . "M.";
    }

    if ($reflectHost) {
        my $newOptionValue = OptionValue->new(key => 'SMBIOS.reflectHost',
                                              value => 'TRUE');
        my @extraConfig = ($newOptionValue);
        $specArgs{extraConfig} = \@extraConfig;
        $msg .= " reflectHost enabled.";
    }

    my $configSpec = VirtualMachineConfigSpec->new(%specArgs);
    eval {
        my $task = $vm->ReconfigVM_Task(spec => $configSpec);
        getTaskStatus($session, $task, $msg);
    };
    if ( $@ ) {
        my $msg = "Failed to resize VM: $@";
        $logger->error($msg);
        print "ERROR: $msg\n";
        exit 9;
    }
}

# Sets up the ESXi networking for nested virtualization
sub setupEsxiNetwork {
    my $session = shift;
    my $host = shift;
    my $vSwithName = shift

    # 1. Set "VM Network"" port group on vSwitch0 to promiscuous mode.
    # 2. Create a port group "vhost_pg" on given vSwitch.
    #    Set the VLAN ID to All(4095).  
    #    Edit the port group and set to promiscuous mode.

    my $hostView = getHostView($session, 0, $host);
    my $networkView = $session->get_view(mo_ref => $hostView->configManager->networkSystem);
    updatePortGroup($networkView, "VM Network", "vSwitch0", 0);
    addPortGroup($networkView, "vhost_pg", $vSwithName, 4095);
}

# Creates a port group
sub addPortGroup {
    my ($networkView, $pgName, $vSwitch, $vlan) = @_;
    my $logger = getLogger();

    my $portGroups = $networkView->networkConfig->portgroup;
    my $found = 0;
    foreach (@$portGroups) {
        my $spec = $_->spec;
        if (defined($spec)) {
            if ($spec->vswitchName eq $vSwitch && $spec->name eq $pgName) {
                $found = 1;
                last;
            }
        }
    }

    if ($found) {
        my $msg = "WARN: Port group \"$pgName\" already exists.";
        $logger->warn($msg);
        print "WARN: $msg\n";

        # Just update the port group, if one is found
        updatePortGroup($networkView, $pgName, $vSwitch, $vlan);
    } else {
        my $securityPolicy = new HostNetworkSecurityPolicy(
            allowPromiscuous => 1,
            forgedTransmits => 1,
            macChanges => 1,
        );
        my $networkPolicy = new HostNetworkPolicy(
            security => $securityPolicy
        );
        $vlan = 0 unless (defined $vlan);
        my $hostPGSpec = new HostPortGroupSpec (
            name => $pgName, 
            policy => $networkPolicy,
            vlanId => $vlan, 
            vswitchName => $vSwitch);
        eval {
            $networkView->AddPortGroup(_this => $networkView, portgrp => $hostPGSpec);
        };
        if ($@) {
            my $msg = "ERROR: Could not add port group \"$pgName\" on vSwitch \"$vSwitch\".";
            $logger->error($msg);
            print "ERROR: $msg\n";
            exit 9;
        }
    }
}

# Updates a given port group
sub updatePortGroup {
    my ($networkView, $pgName, $vSwitch, $vlan) = @_;
    my $logger = getLogger();

    my $portGroups = $networkView->networkConfig->portgroup;
    my $found = 0;
    foreach (@$portGroups) {
        my $spec = $_->spec;
        if (defined($spec)) {
            if ($spec->vswitchName eq $vSwitch && $spec->name eq $pgName) {
                $found = 1;
                last;
            }
        }
    }

    # VM Network port group should always exist.  It is created by default on ESXi deployments.
    unless ($found) {
        my $msg = "WARN: Could not find port group \"$pgName\" on vSwitch \"$vSwitch\".";
        $logger->warn($msg);
        print "WARN: $msg\n";

        addPortGroup($networkView, $pgName, $vSwitch, $vlan);
    }

    # Override existing network policy with entirely new policy
    my $securityPolicy = new HostNetworkSecurityPolicy(
        allowPromiscuous => 1,
        forgedTransmits => 1,
        macChanges => 1,
    );
    my $networkPolicy = new HostNetworkPolicy(
        security => $securityPolicy
    );
    $vlan = 0 unless (defined $vlan);
    my $hostPGSpec = new HostPortGroupSpec (
        name => $pgName, 
        policy => $networkPolicy,
        vlanId => $vlan, 
        vswitchName => $vSwitch);
    eval {
        $networkView->UpdatePortGroup(pgName => $pgName, portgrp => $hostPGSpec);
    };
    if ($@) {
        my $msg = "ERROR: Could not update port group \"$pgName\" on vSwitch \"$vSwitch\".";
        $logger->error($msg);
        print "ERROR: $msg\n";
        exit 9;
    }
}

# Adds a host to a datacenter
sub addHostToDatacenter {
    my $session = shift;
    my $hostIp = shift;
    my $user = shift;
    my $passwd = shift;
    my $datacenterName = shift;

    my $logger = getLogger();
    $logger->info("Adding ESXi virtual host $hostIp to datacenter.");

    my $certificate = getEsxCertificate(esx_host => $hostIp, esx_user => $user,
                                        esx_pass => $passwd);
    my $thumbprint  = generateSslThumbprint( pem => $certificate );

    my $dcViews = $session->find_entity_views(view_type => 'Datacenter', filter => {name => $datacenterName });
    foreach (@$dcViews) {
        my $dc = $_;
        my $hostFolder = $dc->hostFolder;

        $hostFolder = $session->get_view(mo_ref => $hostFolder);
        my $spec = HostConnectSpec->new(
            force => 'false',
            hostName => $hostIp,
            userName => $user,
            password => $passwd,
            sslThumbprint => $thumbprint);
        eval {
            my $task = $hostFolder->AddStandaloneHost_Task(spec => $spec,
                                                           addConnected => 1);
            waitOnTask($session, $task, "ESXi virtual host added.");
        };
        if ( $@ ) {
            my $mess = "Failed to add ESXi virtual host";
            $logger->error("$mess: $@");
            print "ERROR: $mess.\n";
            exit 9;
        }
    }
}

# Adds a host to a cluster
sub addHostToCluster {
    my $session = shift;
    my $hostIp = shift;
    my $user = shift;
    my $passwd = shift;
    my $clusterName = shift;

    my $logger = getLogger();
    $logger->info("Adding ESXi virtual host $hostIp to cluster.");

    my $certificate = getEsxCertificate(esx_host => $hostIp, esx_user => $user,
                                        esx_pass => $passwd);
    my $thumbprint  = generateSslThumbprint( pem => $certificate );
    my $cluster = $session->find_entity_view(view_type => 'ClusterComputeResource',
                                             filter => {name => $clusterName},
                                             properties => ['name']);
    if (!defined $cluster) {
        print "ERROR: Could not find cluster $clusterName.\n";
        exit 9;
    }

    my $spec = HostConnectSpec->new(
        force => 'false',
        hostName => $hostIp,
        userName => $user,
        password => $passwd,
        sslThumbprint => $thumbprint);
    my $task = $cluster->AddHost_Task(spec => $spec, asConnected => "true");
    waitOnTask($session, $task, "ESXi virtual host added.");
}

# Creates a datacenter
sub createDatacenter {
    my $session = shift;
    my $datacenterName = shift;

    my $logger = getLogger();
    $logger->info("Creating datacenter $datacenterName.");

    # Do not create a new datacenter if one already exists
    my $datacenters = $session->find_entity_views(view_type => 'Datacenter', filter => {name=> $datacenterName});
    foreach (@$datacenters) {
        my $found = $_->name;
        if ($found eq $datacenterName) {
            return;
        }
    }

    my $serviceContent = $session->get_service_content();
    my $rootFolder = $serviceContent->{'rootFolder'};
    my $rootFolderView = $session->get_view(mo_ref => $rootFolder);
    my $newDc = $rootFolderView->CreateDatacenter(name => $datacenterName);
    $logger->info("Created $datacenterName datacenter.");
}

# Creates a cluster
sub createCluster {
    my $session = shift;
    my $datacenterName = shift;  # Datacenter to create cluster in
    my $clusterName = shift;

    my $logger = getLogger();
    my $cluster = $session->find_entity_views(view_type => 'ClusterComputeResource', filter => {name => $clusterName});
    if (defined $cluster && @$cluster > 0) {
        $logger->info("Using cluster $clusterName.");
        return;
    }

    $logger->info("Creating cluster $clusterName.");

    my $datacenter = $session->find_entity_view(view_type => 'Datacenter',
                                                properties=>['hostFolder'],
                                                filter => {name => $datacenterName});
    my $hostFolder = $session->get_view(mo_ref => $datacenter->hostFolder);
    if (defined $hostFolder) {
        my $spec = ClusterConfigSpec->new();
        my $task = $hostFolder->CreateCluster(spec => $spec, name => $clusterName);
        $logger->info("Created $clusterName cluster.");
    } else {
        my $msg = "Could not find datacenter $datacenterName.";
        $logger->error($msg);
        print "ERROR: $msg\n";
        exit 9;
    }
}

1;
