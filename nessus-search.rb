#!/usr/bin/env ruby
#
# gem install ruby-nessus
#

require 'nessus'
require 'optparse'

class MissingRequiredOption < StandardError; end

class NessusParser
  attr_reader :nessus_parse, :hosts, :critical_list, 
              :high_list, :medium_list, :low_list, :info_list
              
  def initialize(nessus_file)
    @scans = []
    Nessus::Parse.new(nessus_file) {|scan| @scans << scan}
  end

  # def vulnerabilities
  #   events = {critical: [], high: [], medium: [], low: [], info: []}
  #   @scans.flatten.uniq.each do |scan|
  #     scan.hosts.each do |host|
  #       events[:critical] << host.critical_severity_events.to_a
  #       events[:high]     << host.high_severity_events.to_a
  #       events[:medium]   << host.medium_severity_events.to_a
  #       events[:low]      << host.low_severity_events.to_a
  #       events[:info]     << host.informational_severity_events.to_a      
  #     end
  #   end

  #   # events[:critical]&.flatten!
  #   # events[:high]&.flatten!
  #   # events[:medium]&.flatten!
  #   # events[:low]&.flatten!
  #   # events[:info]&.flatten!

  #   events
  # end

  # ruby nessus-findings.rb -p nessus-scans/sp/ -l
  def list_vulnerabilities

    @critical_list = []
    @high_list     = []
    @medium_list   = []
    @low_list      = []
    @info_list     = []


    @scans.flatten.uniq.each do |scan|
      scan.hosts.each do |host|
        @critical_list << host.critical_severity_events&.map(&:name)
        @high_list     << host.high_severity_events&.map(&:name)
        @medium_list   << host.medium_severity_events&.map(&:name)
        @low_list      << host.low_severity_events&.map(&:name)
        @info_list     << host.informational_severity_events&.map(&:name)
      end
    end
    
    self
  end

  def list_services
    info_list = []
    @scans.flatten.uniq.each do |scan|
      scan.hosts.each do |host|
        info_list << host.informational_severity_events.to_a
      end
    end

    services = []
    info_list.flatten.each do |event|
      if event.name =~ /Service Detection/i
        # puts 11111
        services << event.port
      end
    end
    services.uniq
  end

  def find_vulnerabilities(vuln_name)
    vulns = []
    @scans.flatten.uniq.each do |scan|
      scan.hosts.each do |host|
        all_findings = []
        all_findings << host.critical_severity_events.to_a
        all_findings << host.high_severity_events.to_a
        all_findings << host.medium_severity_events.to_a
        all_findings << host.low_severity_events.to_a
        all_findings << host.informational_severity_events.to_a
        
        all_findings.flatten.uniq&.map do |event|
          if event.name =~ /.*#{vuln_name}.*/i
            vulns << "#{event.risk.ljust(10)}#{event.name}"
          end
        end
      end
    end

    vulns.uniq
  end

  # ruby nessus-findings.rb -p nessus-scans/sp/ -V "X11 Server Unauthenticated Access"
  def find_hosts_by_vulnerability(vuln_name, opts={inc_port: true})
    vuln_hosts = []
    @scans.flatten.uniq.each do |scan|
      scan.hosts.each do |host|
        all_findings = []
        all_findings << host.critical_severity_events.to_a
        all_findings << host.high_severity_events.to_a
        all_findings << host.medium_severity_events.to_a
        all_findings << host.low_severity_events.to_a
        all_findings << host.informational_severity_events.to_a
        
        all_findings.flatten.uniq&.map do |event|
          if event.name =~ /#{vuln_name}/i
            if opts[:inc_port]
              vuln_hosts << ["#{host.ip} #{event.port}", (event.output ? event.output&.squeeze : "----- NO OUTPUT AVAILABLE -----")]
            else
              vuln_hosts << [host.ip, (event.output ? event.output&.squeeze : "----- NO OUTPUT AVAILABLE -----")]
            end 
          end
        end
      end
    end
    vuln_hosts.uniq
  end

  # ruby nessus-findings.rb -p nessus-scans/sp/ -S tomcat
  def find_hosts_by_service(srv_name)
    hosts = []
    @scans.flatten.uniq.each do |scan|
      scan.hosts.each do |host|
        host.informational_severity_events.map do |event|
          if event.name =~ /#{srv_name}/i
            hosts << "#{host.ip} #{event.port}"
          end
        end
      end
    end
    hosts
  end

  def find_vuln_host_by_cve(cve)
    found = {vuln_name: nil, hosts: []}
    
    @scans.flatten.uniq.each do |scan|
      scan.hosts.each do |host|
        all_findings = []
        all_findings << host.critical_severity_events.to_a
        all_findings << host.high_severity_events.to_a
        all_findings << host.medium_severity_events.to_a
        all_findings << host.low_severity_events.to_a
        
        all_findings.flatten.uniq&.map do |event|
          if event.cve.match? /#{cve.upcase}/i
            found[:vuln_name] = event.name #if found[:vuln_name].nil?
            found[:hosts] << host.ip
          end
        end
      end
    end

    found
  end

  # ruby nessus-findings.rb -p nessus-scans/sp/ --ip 10.1.22.11 
  def ip_vulnerabilties(ip)
    @critical_list = []
    @high_list     = []
    @medium_list   = []
    @low_list      = []
    @info_list     = []    
    @scans.flatten.uniq.each do |scan|
      scan.hosts.each do |host|
        next unless host.ip == ip                
        @critical_list << host.critical_severity_events&.map(&:name)
        @high_list     << host.high_severity_events&.map(&:name)
        @medium_list   << host.medium_severity_events&.map(&:name)
        @low_list      << host.low_severity_events&.map(&:name)
        @info_list     << host.informational_severity_events&.map(&:name)
      end
    end

    self
  end

  def vuln_info(vuln_name)
    info = {}

    @scans.flatten.uniq.each do |scan|
      scan.hosts.each do |host|
        all_findings = []
        all_findings << host.critical_severity_events.to_a
        all_findings << host.high_severity_events.to_a
        all_findings << host.medium_severity_events.to_a
        all_findings << host.low_severity_events.to_a
        all_findings << host.informational_severity_events.to_a
        
        event = all_findings.flatten.uniq&.select {|e| e.name.match? /.*#{vuln_name}.*/i}.first

        if event
          info[:name]        = event.name
          info[:severity]    = event.severity
          info[:risk]        = event.risk
          info[:description] = event.description
          info[:solution]    = event.solution
          info[:cve]         = event.cve
          info[:output]      = event.output ? event.output&.squeeze : "----- NO OUTPUT AVAILABLE -----"
          break
        end
      end
      break
    end
    return info
  end

end


params = {}
option_parser = OptionParser.new do |opts|
  opts.on("-p PATH", "--path PATH", "File or directory path") do |n|
    path = n
  end

  opts.on("-l RISK", 
    "--list RISK", 
    %w[critical high medium low informational all], 
    "List all findings", 
    "  risk levels: critical, high, medium, low, informational, all") {|n| v = n}

  opts.on("-v", "--vuln VUL_NAME", "Find vulnerabilities that match name") {|n| v = n}
  
  opts.on("-V", "--vuln-hosts VUL_NAME", "Find vulnerable hosts by specific vulnerability name") {|n| v = n}

  opts.on("--output", "Show the vulnerability output for the vulnerable hosts (verbose outputs) use it with '-V/--vuln-hosts'") {|n| v = n}

  opts.on("-i", "--ip IP_ADDR", "Find vulnerabilities for a specific IP address") {|n| v = n}

  opts.on("-S", "--services", "List discovered services with its ports") {|n| v = n}

  opts.on("-s", "--srv SRV_NAME", "Find hosts by service name (use \"\" to list all services for all hosts)") {|n| v = n}

  opts.on("-c", "--cve CVE", "Find vulnerability and hosts by CVE") {|n| v = n}

  opts.on("-I", "--info VUL_NAME", "Get the vulnerability information (Only exact name maches)") {|n| v = n}
  
  opts.on("-h", "--help", "Prints this help") do
    puts opts
    exit
  end
end

def process_path(path)
  if File.exist? path
    if File.directory?(path)
      paths = Dir.glob(File.join(path, "*.nessus")) 
    elsif File.file?(path)
      paths = [path]
    else
      puts "WTF? #{path}"
      exit!
    end
  else
    puts "[!] Path doesn't exist! #{path}"
    exit! 
  end
end

begin
  option_parser.parse!(into: params)
  raise MissingRequiredOption if params[:path].nil?  
  paths = process_path(params[:path])

  @critical = []
  @high     = []
  @medium   = []
  @low      = []
  @info     = []
  
  if params[:list]
    paths.each do |file|
      puts "[*] Parsing '" + file + "'"
      list = NessusParser.new(file).list_vulnerabilities
      @critical << list.critical_list if (params[:list] == "all" || params[:list] == "critical")
      @high     << list.high_list     if (params[:list] == "all" || params[:list] == "high")
      @medium   << list.medium_list   if (params[:list] == "all" || params[:list] == "medium")
      @low      << list.low_list      if (params[:list] == "all" || params[:list] == "low")
      @info     << list.info_list     if (params[:list] == "all" || params[:list] == "informational")
    end

    if params[:list] == "all" || params[:list] == "critical"
      critical = @critical&.flatten.uniq
      puts "\n[+] Critical: (#{critical.size})"
      puts critical
      puts "----------"
    end
    
    if params[:list] == "all" || params[:list] == "high"
      high = @high&.flatten.uniq
      puts "\n[+] High: (#{high.size})"
      puts high
      puts "----------"
    end
    
    if params[:list] == "all" || params[:list] == "medium"
      medium = @medium&.flatten.uniq
      puts "\n[+] Medium: (#{medium.size})"
      puts medium
      puts "----------"
    end
    
    if params[:list] == "all" || params[:list] == "low"
      low = @low&.flatten.uniq
      puts "\n[+] Low: (#{low.size})"
      puts low
      puts "----------"
    end
    
    if params[:list] == "all" || params[:list] == "informational"
      info = @info.flatten.uniq
      puts "\n[+] Informational: (#{info.size})"
      puts info
      puts "----------"  
    end
  end

  if params[:"vuln-hosts"]
    hosts = []
    paths.each do |file|
      puts "[*] Parsing '" + file + "'"
      hosts.concat NessusParser.new(file).find_hosts_by_vulnerability(params[:"vuln-hosts"])
    end
    hosts     = hosts&.sort.uniq
    hosts_ips = hosts.map(&:first).uniq

    puts "\n[+] Vulnerable hosts: (#{hosts_ips.size})"
    if params[:output]
      puts hosts
    else
      puts hosts_ips
    end    
  end

  if params[:srv]
    hosts = []
    paths.each do |file|
      puts "[*] Parsing '" + file + "'"
      hosts << NessusParser.new(file).find_hosts_by_service(params[:srv])
    end

    hosts = hosts&.flatten.sort.uniq
    puts "\n[+] hosts with #{params[:srv]} service: (#{hosts.size})"
    puts hosts
  end

  if params[:ip]
    paths.each do |file|
      puts "[*] Parsing '" + file + "'"
      list = NessusParser.new(file).ip_vulnerabilties(params[:ip])
      @critical << list.critical_list
      @high     << list.high_list
      @medium   << list.medium_list
      @low      << list.low_list
      @info     << list.info_list
    end

    puts "\n[*] List of vulnerabilties for '#{params[:ip]}' host"
    critical = @critical&.flatten.uniq
    puts "\n[+] Critical: (#{critical.size})"
    puts critical
    puts "----------"
    
    high = @high&.flatten.uniq
    puts "\n[+] High: (#{high.size})"
    puts high
    puts "----------"
    
    puts @medium&.flatten.uniq
    medium = @medium&.flatten.uniq
    puts "\n[+] Medium: (#{medium.size})"
    puts medium
    puts "----------"
    
    low = @low&.flatten.uniq
    puts "\n[+] Low: (#{low.size})"
    puts low
    puts "----------"
    
    info = @info.flatten.uniq
    puts "\n[+] Informational: (#{info.size})"
    puts "----------"  
  end

  if params[:info]
    paths.each do |file|
      puts "[*] Parsing '" + file + "'"
      info = NessusParser.new(file).vuln_info(params[:info])
      unless info.empty?
        puts "[+] Vulnerability information"        
        puts "- Name: "         , info[:name]
        puts "\n- severity:"    , info[:severity].to_s
        puts "\n- risk: "       , info[:risk]
        puts "\n- description:" , info[:description]
        puts "\n- solution:"    , info[:solution]
        puts "\n- cve:"         , info[:cve]
        puts "\n- Output:"      , info[:output]
        break
      end
    end
  end

  if params[:services]
    services = []
    paths.each do |file|
      puts "[*] Parsing '" + file + "'"
      services << NessusParser.new(file).list_services
    end

    services = services.flatten.map(&:to_s).uniq
    puts "\n[+] List of services: (#{services.size})"
    puts services
  end

  if params[:cve]
    vuln_name = nil
    hosts     = []
    paths.each do |file|
      puts "[*] Parsing '" + file + "'"
      cve = NessusParser.new(file).find_vuln_host_by_cve(params[:cve])    
      vuln_name = cve[:vuln_name] unless cve[:vuln_name].nil?
      hosts << cve[:hosts]
    end
    puts "\n[+] #{vuln_name} (#{params[:cve]})"
    puts hosts.flatten
  end

  if params[:vuln]
    vulns = []
    paths.each do |file|
      puts "[*] Parsing '" + file + "'"
      vulns << NessusParser.new(file).find_vulnerabilities(params[:vuln])
    end

    puts "\n[+] Matching vulnerabilties for '#{params[:vuln]}':"
    puts vulns&.flatten.uniq
  end

rescue OptionParser::MissingArgument
  puts "[!] File or directory path must be provided"
  puts option_parser.help
  exit!
rescue MissingRequiredOption
  puts "[x] Option -p/--path is mandatory!"
  puts option_parser.help
  exit!
rescue OptionParser::InvalidArgument
  puts "[x] Invalid argument!"
  puts option_parser.help
  exit!
end
