#!/usr/bin/ruby
#
# Apache2 log analyzer to count unique ips and number of queries
#
# This script is used to find the unique ips in an apache2 access.log
# and count the number of queries for each ip, the number of errors served
# and the number of queries to secret.html for each ip.
#
#   ApacheLogAnalyzer: Analyzer for a log file given the full or relative path
#

# Apache2 log analyzer
#
#  Build an instance of this class and pass a list of full or relative path(s)
#  to the analyze function to receive a list of unique IP addresses, the total
#  number of queries per IP, the number of queries to secret.html per IP, and
#  the total number of 404 errors served.
#
class ApacheLogAnalyzer

  def initialize
    @total_hits_by_ip = Hash.new(0)
    @total_hits_per_url = Hash.new(0)
    @secret_hits_by_ip = Hash.new(0)
    @error_count = 0
  end

  # Analyze a log file provided the full or relative path
  #
  # Args:
  # - file_name: string -- Full or relative path to a log file
  #
  def analyze(file_name)
    # Regex to match a single octet of an IPv4 address
    octet = /\d{,2}|1\d{2}|2[0-4]\d|25[0-5]/
    # Since an IPv4 address is made of four octets we will string them together
    # to match a full IPv4 address
    ip_regex = /^#{octet}\.#{octet}\.#{octet}\.#{octet}/
    # Regex to match an alphanumeric url ending with .html
    url_regex = /[a-zA-Z0-9]+.html/

    # TODO: Read in the file line by line using a loop
    File.foreach(file_name) do |line|
      ip = ip_regex.match(line)
      # if line.include?("GET")
      url = url_regex.match(line)
      # end
      if line.include?("404")
        error = true
      end
      if line.include?("/secret.html")
        secret = true
      end
    
    # TODO: Match the various regex (IP Address, URL, Secret URL, and 404 Error)
    # and pass them to the count_hits function to be counted
    count_hits(ip, url, secret, error)

    print_hits

    end

  end

  private
  # Count the total and secret queries for a given ip
  #
  # Args:
  # - ip: string -- IP address responsible for the logged entry
  # - url: string -- URL queried for the logged entry
  # - secret: bool -- Whether or not the url queried was secret.html
  # - error: bool -- Whether or not the log entry contained a 404 error
  #
  def count_hits(ip, url, secret, error)
    # TODO: Associate the request with the IP Address
    @total_hits_by_ip["#{ip}"] += 1
    # TODO: Associate the request with the url requested
    @total_hits_per_url["#{url}"] += 1
    # TODO: Associate the request with the IP if the query is for the Secret URL
    if secret == true
      @secret_hits_by_ip["#{ip}"] =+ 1
    end
    # TODO: Keep track of the total number of 404 errors served
    if error == true
      @error_count += 1
    end
  
  end

  # Print the number of queries for each ip to the secret url and in total
  #
  def print_hits
    print_string = 'IP: %s, Total Hits: %s, Secret Hits: %s'
    @total_hits_by_ip.sort.each do |ip, total_hits|
      secret_hits = @secret_hits_by_ip[ip]
      puts sprintf(print_string, ip, total_hits, secret_hits)
    end
    url_print_string = 'URL: %s, Number of Hits: %s'
    @total_hits_per_url.sort.each do |url, url_hits|
      puts sprintf(url_print_string, url, url_hits)
    end
    puts sprintf('Total Errors: %s', @error_count)
  end
end


def usage
  puts "No log files passed, please pass at least one log file.\n\n"
  puts "USAGE: #{$PROGRAM_NAME} file1 [file2 ...]\n\n"
  puts "Analyzes apache2 log files for unique IP addresses and unique URLs."
end


def main
  if ARGV.empty?
    usage
    exit(1)
  end
  ARGV.each do |file_name|
    log_analyzer = ApacheLogAnalyzer.new
    log_analyzer.analyze(file_name)
  end
end


if __FILE__ == $PROGRAM_NAME
  main
end
