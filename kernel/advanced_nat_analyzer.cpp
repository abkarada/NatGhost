#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <chrono>
#include <thread>
#include <algorithm>
#include <map>
#include <unordered_map>
#include <set>
#include <complex>
#include <numeric>
#include <cmath>
#include <fstream>
#include <iomanip>

// STUN message structure
struct STUNHeader {
    uint16_t type;
    uint16_t length;
    uint32_t magic_cookie;
    uint8_t transaction_id[12];
} __attribute__((packed));

// Packet measurement data
struct PacketMeasurement {
    uint16_t assigned_port;
    uint64_t timestamp_us;
    uint32_t sequence_number;
    uint16_t source_port;
    std::string target_ip;
    bool success;
};

// Forward declarations
struct PortPrediction {
    uint16_t predicted_port;
    double confidence;
    std::string method;
    int steps_ahead;
};

class AdvancedNATAnalyzer {
private:
    std::vector<PacketMeasurement> measurements;
    std::string target_stun_server;
    uint16_t stun_port;
    int socket_fd;
    
public:
    AdvancedNATAnalyzer(const std::string& stun_server = "stun.l.google.com", uint16_t port = 19302) 
        : target_stun_server(stun_server), stun_port(port), socket_fd(-1) {
        
        std::cout << "🚀 Advanced C++ NAT Analyzer - High Performance + Pattern Detection" << std::endl;
        std::cout << "Target STUN Server: " << stun_server << ":" << port << std::endl;
    }
    
    ~AdvancedNATAnalyzer() {
        if (socket_fd != -1) {
            close(socket_fd);
        }
    }
    
    bool initialize_socket() {
        socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (socket_fd < 0) {
            perror("Socket creation failed");
            return false;
        }
        
        // Enable source port reuse
        int reuse = 1;
        setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        
        return true;
    }
    
    uint64_t get_timestamp_us() {
        auto now = std::chrono::high_resolution_clock::now();
        return std::chrono::duration_cast<std::chrono::microseconds>(
            now.time_since_epoch()).count();
    }
    
    void create_stun_binding_request(uint8_t* buffer, uint8_t* transaction_id) {
        STUNHeader* header = reinterpret_cast<STUNHeader*>(buffer);
        header->type = htons(0x0001);  // Binding Request
        header->length = 0;  // No attributes for basic request
        header->magic_cookie = htonl(0x2112A442);  // STUN magic cookie
        memcpy(header->transaction_id, transaction_id, 12);
    }
    
    void resolve_hostname_to_ip() {
        // Simple resolution - in production use getaddrinfo
        if (target_stun_server == "stun.l.google.com") {
            target_stun_server = "74.125.250.129";
        }
        std::cout << "📍 Resolved to: " << target_stun_server << std::endl;
    }
    
    bool execute_high_performance_burst(int packet_count, uint16_t start_port = 0) {
        std::cout << "🔥 Starting high-performance burst: " << packet_count << " packets" << std::endl;
        std::cout << "🎯 Strategy: Each packet from different source port for unique NAT sessions" << std::endl;
        
        resolve_hostname_to_ip();
        
        // Prepare target address
        struct sockaddr_in target_addr;
        memset(&target_addr, 0, sizeof(target_addr));
        target_addr.sin_family = AF_INET;
        target_addr.sin_port = htons(stun_port);
        inet_pton(AF_INET, target_stun_server.c_str(), &target_addr.sin_addr);
        
        measurements.clear();
        measurements.reserve(packet_count);
        
        auto start_time = get_timestamp_us();
        
        // Create separate sockets for each source port to get unique NAT mappings
        std::vector<int> sockets(packet_count);
        std::vector<struct sockaddr_in> source_addrs(packet_count);
        
        // Prepare sendmmsg structures
        std::vector<struct mmsghdr> msgs(packet_count);
        std::vector<struct iovec> iovecs(packet_count);
        std::vector<uint8_t> buffers(packet_count * 20);  // 20 bytes per STUN header
        std::vector<uint8_t> transaction_ids(packet_count * 12);
        
        // Create sockets with different source ports
        for (int i = 0; i < packet_count; ++i) {
            sockets[i] = socket(AF_INET, SOCK_DGRAM, 0);
            if (sockets[i] < 0) {
                perror("Socket creation failed");
                return false;
            }
            
            // Bind to specific source port
            memset(&source_addrs[i], 0, sizeof(source_addrs[i]));
            source_addrs[i].sin_family = AF_INET;
            source_addrs[i].sin_addr.s_addr = INADDR_ANY;
            source_addrs[i].sin_port = htons(start_port + 10000 + i);  // Use different source ports
            
            if (bind(sockets[i], (struct sockaddr*)&source_addrs[i], sizeof(source_addrs[i])) < 0) {
                // If bind fails, let kernel choose port
                source_addrs[i].sin_port = 0;
                bind(sockets[i], (struct sockaddr*)&source_addrs[i], sizeof(source_addrs[i]));
            }
            
            uint8_t* buffer = &buffers[i * 20];
            uint8_t* trans_id = &transaction_ids[i * 12];
            
            // Generate unique transaction ID
            for (int j = 0; j < 12; ++j) {
                trans_id[j] = rand() & 0xFF;
            }
            
            create_stun_binding_request(buffer, trans_id);
            
            iovecs[i].iov_base = buffer;
            iovecs[i].iov_len = 20;
            
            msgs[i].msg_hdr.msg_name = &target_addr;
            msgs[i].msg_hdr.msg_namelen = sizeof(target_addr);
            msgs[i].msg_hdr.msg_iov = &iovecs[i];
            msgs[i].msg_hdr.msg_iovlen = 1;
            msgs[i].msg_hdr.msg_control = nullptr;
            msgs[i].msg_hdr.msg_controllen = 0;
            msgs[i].msg_hdr.msg_flags = 0;
        }
        
        std::cout << "📦 Prepared " << packet_count << " STUN messages with unique source ports" << std::endl;
        std::cout << "🚀 Executing individual socket sends for NAT diversity..." << std::endl;
        
        // Send from each socket individually to ensure different NAT sessions
        auto burst_start = get_timestamp_us();
        int sent = 0;
        
        for (int i = 0; i < packet_count; ++i) {
            ssize_t result = sendto(sockets[i], buffers.data() + i * 20, 20, 0,
                                   (struct sockaddr*)&target_addr, sizeof(target_addr));
            if (result > 0) {
                sent++;
            }
        }
        
        auto burst_end = get_timestamp_us();
        
        std::cout << "✅ Burst complete: " << sent << "/" << packet_count << " packets sent" << std::endl;
        
        double burst_duration_s = (burst_end - burst_start) / 1e6;
        double packet_rate = sent / burst_duration_s;
        
        std::cout << "⚡ Burst Performance:" << std::endl;
        std::cout << "   Duration: " << std::fixed << std::setprecision(3) 
                  << burst_duration_s << "s" << std::endl;
        std::cout << "   Rate: " << std::fixed << std::setprecision(0) 
                  << packet_rate << " packets/second" << std::endl;
        
        // Now collect responses for pattern analysis from all sockets
        bool result = collect_stun_responses_multi_socket(sockets, sent, start_time);
        
        // Close all sockets
        for (int sock : sockets) {
            close(sock);
        }
        
        return result;
    }
    
    bool collect_stun_responses(int expected_responses, uint64_t start_time) {
        std::cout << "📡 Collecting STUN responses for pattern analysis..." << std::endl;
        
        // Set socket timeout
        struct timeval timeout;
        timeout.tv_sec = 5;  // 5 seconds timeout
        timeout.tv_usec = 0;
        setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        
        uint8_t response_buffer[1500];
        struct sockaddr_in from_addr;
        socklen_t from_len = sizeof(from_addr);
        
        int responses_received = 0;
        auto collection_start = get_timestamp_us();
        
        while (responses_received < expected_responses) {
            ssize_t bytes_received = recvfrom(socket_fd, response_buffer, sizeof(response_buffer),
                                            0, (struct sockaddr*)&from_addr, &from_len);
            
            if (bytes_received < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    std::cout << "⏰ Timeout reached" << std::endl;
                    break;
                }
                perror("recvfrom failed");
                break;
            }
            
            if (bytes_received < 20) {
                continue;  // Invalid STUN response
            }
            
            // Parse STUN response
            STUNHeader* header = reinterpret_cast<STUNHeader*>(response_buffer);
            
            if (ntohs(header->type) == 0x0101) {  // Binding Success Response
                uint16_t assigned_port = parse_mapped_address(response_buffer, bytes_received);
                
                if (assigned_port > 0) {
                    PacketMeasurement measurement;
                    measurement.assigned_port = assigned_port;
                    measurement.timestamp_us = get_timestamp_us();
                    measurement.sequence_number = responses_received;
                    measurement.source_port = 0;  // We're not binding to specific source ports
                    measurement.target_ip = target_stun_server;
                    measurement.success = true;
                    
                    measurements.push_back(measurement);
                    responses_received++;
                    
                    if (responses_received % 10 == 0 || responses_received < 20) {
                        std::cout << "📊 Response " << responses_received 
                                  << ": Port " << assigned_port << std::endl;
                    }
                }
            }
        }
        
        auto collection_end = get_timestamp_us();
        double collection_duration = (collection_end - collection_start) / 1e6;
        
        std::cout << "✅ Response Collection Complete:" << std::endl;
        std::cout << "   Received: " << responses_received << "/" << expected_responses << std::endl;
        std::cout << "   Duration: " << collection_duration << "s" << std::endl;
        std::cout << "   Success Rate: " << (100.0 * responses_received / expected_responses) << "%" << std::endl;
        
        return responses_received > 0;
    }
    
    uint16_t parse_mapped_address(uint8_t* buffer, size_t length) {
        // Skip STUN header (20 bytes)
        uint8_t* ptr = buffer + 20;
        uint8_t* end = buffer + length;
        
        while (ptr + 4 <= end) {
            uint16_t attr_type = ntohs(*reinterpret_cast<uint16_t*>(ptr));
            uint16_t attr_length = ntohs(*reinterpret_cast<uint16_t*>(ptr + 2));
            ptr += 4;
            
            if (ptr + attr_length > end) break;
            
            // MAPPED-ADDRESS (0x0001) or XOR-MAPPED-ADDRESS (0x0020)
            if (attr_type == 0x0001 || attr_type == 0x0020) {
                if (attr_length >= 8) {
                    uint16_t port = ntohs(*reinterpret_cast<uint16_t*>(ptr + 2));
                    
                    // If XOR-MAPPED-ADDRESS, XOR with magic cookie
                    if (attr_type == 0x0020) {
                        port ^= 0x2112;
                    }
                    
                    return port;
                }
            }
            
            ptr += attr_length;
            // Align to 4-byte boundary
            while ((ptr - buffer) % 4 != 0 && ptr < end) ptr++;
        }
        
        return 0;  // No mapped address found
    }
    
    bool collect_stun_responses_multi_socket(const std::vector<int>& sockets, int expected_responses, uint64_t start_time) {
        std::cout << "📡 Collecting STUN responses from multiple sockets..." << std::endl;
        
        // Set socket timeout for all sockets
        struct timeval timeout;
        timeout.tv_sec = 3;  // 3 seconds timeout per socket
        timeout.tv_usec = 0;
        
        for (int sock : sockets) {
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        }
        
        uint8_t response_buffer[1500];
        struct sockaddr_in from_addr;
        socklen_t from_len = sizeof(from_addr);
        
        int responses_received = 0;
        auto collection_start = get_timestamp_us();
        
        // Collect responses from each socket
        for (size_t i = 0; i < sockets.size() && responses_received < expected_responses; ++i) {
            ssize_t bytes_received = recvfrom(sockets[i], response_buffer, sizeof(response_buffer),
                                            0, (struct sockaddr*)&from_addr, &from_len);
            
            if (bytes_received >= 20) {  // Valid STUN response size
                STUNHeader* header = reinterpret_cast<STUNHeader*>(response_buffer);
                
                if (ntohs(header->type) == 0x0101) {  // Binding Success Response
                    uint16_t assigned_port = parse_mapped_address(response_buffer, bytes_received);
                    
                    if (assigned_port > 0) {
                        PacketMeasurement measurement;
                        measurement.assigned_port = assigned_port;
                        measurement.timestamp_us = get_timestamp_us();
                        measurement.sequence_number = responses_received;
                        measurement.source_port = 10000 + i;  // Track which socket
                        measurement.target_ip = target_stun_server;
                        measurement.success = true;
                        
                        measurements.push_back(measurement);
                        responses_received++;
                        
                        if (responses_received % 10 == 0 || responses_received < 20) {
                            std::cout << "📊 Response " << responses_received 
                                      << " (src:" << measurement.source_port << "): Port " 
                                      << assigned_port << std::endl;
                        }
                    }
                }
            }
        }
        
        auto collection_end = get_timestamp_us();
        double collection_duration = (collection_end - collection_start) / 1e6;
        
        std::cout << "✅ Multi-socket Response Collection Complete:" << std::endl;
        std::cout << "   Received: " << responses_received << "/" << expected_responses << std::endl;
        std::cout << "   Duration: " << collection_duration << "s" << std::endl;
        std::cout << "   Success Rate: " << (100.0 * responses_received / expected_responses) << "%" << std::endl;
        
        return responses_received > 0;
    }
    
    // ====================== PATTERN ANALYSIS METHODS ======================
    
    void run_comprehensive_analysis() {
        if (measurements.empty()) {
            std::cout << "❌ No measurement data available for analysis" << std::endl;
            return;
        }
        
        std::cout << "\n🔬 COMPREHENSIVE PATTERN ANALYSIS" << std::endl;
        std::cout << "=" << std::string(50, '=') << std::endl;
        std::cout << "📊 Dataset: " << measurements.size() << " measurements" << std::endl;
        
        // Extract port sequence
        std::vector<uint16_t> ports;
        for (const auto& m : measurements) {
            ports.push_back(m.assigned_port);
        }
        
        basic_statistics_analysis(ports);
        entropy_analysis(ports);
        delta_port_analysis(ports);
        autocorrelation_analysis(ports);
        periodicity_detection(ports);
        berlekamp_massey_analysis(ports);
        lfsr_prediction(ports);
        markov_chain_analysis(ports);
        bit_plane_entropy_analysis(ports);
        chi_square_uniformity_test(ports);
        spectral_analysis(ports);
        
        save_results_to_file();
    }
    
    void basic_statistics_analysis(const std::vector<uint16_t>& ports) {
        std::cout << "\n📈 BASIC STATISTICS:" << std::endl;
        
        uint16_t min_port = *std::min_element(ports.begin(), ports.end());
        uint16_t max_port = *std::max_element(ports.begin(), ports.end());
        double mean_port = std::accumulate(ports.begin(), ports.end(), 0.0) / ports.size();
        
        double variance = 0.0;
        for (uint16_t port : ports) {
            variance += (port - mean_port) * (port - mean_port);
        }
        variance /= ports.size();
        double std_dev = std::sqrt(variance);
        
        std::cout << "   Port Range: " << min_port << " - " << max_port << std::endl;
        std::cout << "   Port Span: " << (max_port - min_port) << std::endl;
        std::cout << "   Mean Port: " << std::fixed << std::setprecision(1) << mean_port << std::endl;
        std::cout << "   Std Dev: " << std::fixed << std::setprecision(1) << std_dev << std::endl;
        
        // Unique ports
        std::set<uint16_t> unique_ports(ports.begin(), ports.end());
        std::cout << "   Unique Ports: " << unique_ports.size() << "/" << ports.size();
        if (unique_ports.size() < ports.size()) {
            std::cout << " (REUSE DETECTED!)";
        }
        std::cout << std::endl;
    }
    
    void entropy_analysis(const std::vector<uint16_t>& ports) {
        std::cout << "\n🎯 ENTROPY ANALYSIS:" << std::endl;
        
        std::map<uint16_t, int> freq;
        for (uint16_t port : ports) {
            freq[port]++;
        }
        
        double shannon_entropy = 0.0;
        for (const auto& [port, count] : freq) {
            double p = (double)count / ports.size();
            shannon_entropy -= p * std::log2(p);
        }
        
        double max_entropy = std::log2(ports.size());
        double entropy_ratio = shannon_entropy / max_entropy;
        
        std::cout << "   Shannon Entropy: " << std::fixed << std::setprecision(3) 
                  << shannon_entropy << " bits" << std::endl;
        std::cout << "   Max Possible: " << std::fixed << std::setprecision(3) 
                  << max_entropy << " bits" << std::endl;
        std::cout << "   Entropy Ratio: " << std::fixed << std::setprecision(3) 
                  << entropy_ratio << " (" << (entropy_ratio * 100) << "%)" << std::endl;
    }
    
    void delta_port_analysis(const std::vector<uint16_t>& ports) {
        if (ports.size() < 2) return;
        
        std::cout << "\n📊 PORT DELTA ANALYSIS:" << std::endl;
        
        std::map<int32_t, int> delta_freq;
        std::vector<int32_t> deltas;
        
        for (size_t i = 1; i < ports.size(); ++i) {
            int32_t delta = (int32_t)ports[i] - (int32_t)ports[i-1];
            deltas.push_back(delta);
            delta_freq[delta]++;
        }
        
        // Most common deltas
        std::vector<std::pair<int32_t, int>> sorted_deltas(delta_freq.begin(), delta_freq.end());
        std::sort(sorted_deltas.begin(), sorted_deltas.end(), 
                 [](const auto& a, const auto& b) { return a.second > b.second; });
        
        std::cout << "   Most Common Deltas:" << std::endl;
        for (size_t i = 0; i < std::min(size_t(5), sorted_deltas.size()); ++i) {
            std::cout << "     Δ" << sorted_deltas[i].first 
                      << ": " << sorted_deltas[i].second << " times" << std::endl;
        }
        
        // Delta statistics
        double mean_delta = std::accumulate(deltas.begin(), deltas.end(), 0.0) / deltas.size();
        std::cout << "   Mean Delta: " << std::fixed << std::setprecision(1) << mean_delta << std::endl;
    }
    
    void autocorrelation_analysis(const std::vector<uint16_t>& ports) {
        if (ports.size() < 10) return;
        
        std::cout << "\n🔄 AUTOCORRELATION ANALYSIS:" << std::endl;
        
        double mean = std::accumulate(ports.begin(), ports.end(), 0.0) / ports.size();
        
        std::cout << "   Lag | Correlation" << std::endl;
        std::cout << "   ----|------------" << std::endl;
        
        for (int lag = 1; lag <= std::min(10, (int)ports.size()/2); ++lag) {
            double numerator = 0.0;
            double denominator = 0.0;
            
            for (size_t i = 0; i + lag < ports.size(); ++i) {
                numerator += (ports[i] - mean) * (ports[i + lag] - mean);
            }
            
            for (size_t i = 0; i < ports.size(); ++i) {
                denominator += (ports[i] - mean) * (ports[i] - mean);
            }
            
            double correlation = (denominator != 0) ? numerator / denominator : 0.0;
            
            std::cout << "   " << std::setw(3) << lag << " | " 
                      << std::fixed << std::setprecision(4) << correlation;
            
            if (std::abs(correlation) > 0.1) {
                std::cout << " *** SIGNIFICANT ***";
            }
            std::cout << std::endl;
        }
    }
    
    void periodicity_detection(const std::vector<uint16_t>& ports) {
        std::cout << "\n🔄 PERIODICITY DETECTION:" << std::endl;
        
        // Look for repeating subsequences
        std::map<size_t, int> period_candidates;
        
        for (size_t period = 2; period <= ports.size()/3; ++period) {
            bool is_periodic = true;
            for (size_t i = 0; i + period < ports.size(); ++i) {
                if (ports[i] != ports[i + period]) {
                    is_periodic = false;
                    break;
                }
            }
            
            if (is_periodic) {
                period_candidates[period]++;
            }
        }
        
        if (period_candidates.empty()) {
            std::cout << "   No clear periodicity detected" << std::endl;
        } else {
            std::cout << "   Potential Periods:" << std::endl;
            for (const auto& [period, confidence] : period_candidates) {
                std::cout << "     Period " << period << " (confidence: " << confidence << ")" << std::endl;
            }
        }
    }
    
    int berlekamp_massey(const std::vector<int>& sequence) {
        int n = sequence.size();
        std::vector<int> c(n), b(n);
        c[0] = b[0] = 1;
        int l = 0, m = -1;
        
        for (int i = 0; i < n; ++i) {
            int d = sequence[i];
            for (int j = 1; j <= l; ++j) {
                d ^= c[j] * sequence[i - j];
            }
            
            if (d == 0) continue;
            
            std::vector<int> t = c;
            for (int j = 0; j < n - i + m; ++j) {
                if (b[j]) c[j + i - m] ^= 1;
            }
            
            if (2 * l <= i) {
                l = i + 1 - l;
                m = i;
                b = t;
            }
        }
        
        return l;
    }
    
    void berlekamp_massey_analysis(const std::vector<uint16_t>& ports) {
        std::cout << "\n🧮 BERLEKAMP-MASSEY LINEAR COMPLEXITY:" << std::endl;
        
        // Convert ports to bit sequence
        std::vector<int> bit_sequence;
        for (uint16_t port : ports) {
            for (int i = 15; i >= 0; --i) {
                bit_sequence.push_back((port >> i) & 1);
            }
        }
        
        int linear_complexity = berlekamp_massey(bit_sequence);
        
        std::cout << "   Bit Sequence Length: " << bit_sequence.size() << std::endl;
        std::cout << "   Linear Complexity: " << linear_complexity << std::endl;
        std::cout << "   Complexity Ratio: " << std::fixed << std::setprecision(3) 
                  << (double)linear_complexity / bit_sequence.size() << std::endl;
        
        if (linear_complexity < bit_sequence.size() / 2) {
            std::cout << "   ⚠️  LOW COMPLEXITY - PREDICTABLE SEQUENCE DETECTED!" << std::endl;
        } else {
            std::cout << "   ✅ High complexity - appears random" << std::endl;
        }
    }
    
    void lfsr_prediction(const std::vector<uint16_t>& ports) {
        if (ports.size() < 10) return;
        
        std::cout << "\n🔮 LFSR PREDICTION:" << std::endl;
        
        // Convert to bit sequence
        std::vector<int> bits;
        for (uint16_t port : ports) {
            for (int i = 15; i >= 0; --i) {
                bits.push_back((port >> i) & 1);
            }
        }
        
        int complexity = berlekamp_massey(bits);
        
        if (complexity < bits.size() / 4) {
            std::cout << "   ⚡ LFSR Pattern Detected - Attempting Prediction..." << std::endl;
            
            // Simple prediction attempt (would need full Berlekamp-Massey implementation)
            std::cout << "   Next predicted ports (simplified):" << std::endl;
            
            // Use last few ports to predict pattern
            if (ports.size() >= 4) {
                std::vector<int32_t> deltas;
                for (size_t i = 1; i < std::min(size_t(4), ports.size()); ++i) {
                    deltas.push_back((int32_t)ports[i] - (int32_t)ports[i-1]);
                }
                
                // Predict next ports based on delta pattern
                uint16_t last_port = ports.back();
                for (int i = 0; i < 3; ++i) {
                    int32_t predicted_delta = deltas[i % deltas.size()];
                    uint16_t predicted_port = (uint16_t)(last_port + predicted_delta);
                    std::cout << "     Prediction " << (i+1) << ": " << predicted_port << std::endl;
                    last_port = predicted_port;
                }
            }
        } else {
            std::cout << "   No clear LFSR pattern detected" << std::endl;
        }
    }
    
    void markov_chain_analysis(const std::vector<uint16_t>& ports) {
        if (ports.size() < 3) return;
        
        std::cout << "\n🔗 MARKOV CHAIN ANALYSIS:" << std::endl;
        
        // Build transition matrix (simplified - use port % 256 for manageable state space)
        std::map<uint8_t, std::map<uint8_t, int>> transitions;
        
        for (size_t i = 1; i < ports.size(); ++i) {
            uint8_t from_state = ports[i-1] & 0xFF;
            uint8_t to_state = ports[i] & 0xFF;
            transitions[from_state][to_state]++;
        }
        
        // Find most predictable transitions
        std::vector<std::tuple<uint8_t, uint8_t, double>> strong_transitions;
        
        for (const auto& [from, to_map] : transitions) {
            int total = 0;
            for (const auto& [to, count] : to_map) {
                total += count;
            }
            
            for (const auto& [to, count] : to_map) {
                double probability = (double)count / total;
                if (probability > 0.5) {  // Strong transition
                    strong_transitions.emplace_back(from, to, probability);
                }
            }
        }
        
        if (strong_transitions.empty()) {
            std::cout << "   No strong Markov transitions detected" << std::endl;
        } else {
            std::cout << "   Strong Transitions (>50% probability):" << std::endl;
            for (const auto& [from, to, prob] : strong_transitions) {
                std::cout << "     " << (int)from << " → " << (int)to 
                          << " (" << std::fixed << std::setprecision(1) << (prob*100) << "%)" << std::endl;
            }
        }
    }
    
    void bit_plane_entropy_analysis(const std::vector<uint16_t>& ports) {
        std::cout << "\n🎯 BIT-PLANE ENTROPY:" << std::endl;
        
        for (int bit = 15; bit >= 0; --bit) {
            int ones = 0;
            for (uint16_t port : ports) {
                if ((port >> bit) & 1) ones++;
            }
            
            int zeros = ports.size() - ones;
            double p1 = (double)ones / ports.size();
            double p0 = (double)zeros / ports.size();
            
            double entropy = 0.0;
            if (p1 > 0) entropy -= p1 * std::log2(p1);
            if (p0 > 0) entropy -= p0 * std::log2(p0);
            
            std::cout << "   Bit " << std::setw(2) << bit << ": " 
                      << std::fixed << std::setprecision(4) << entropy;
            
            if (entropy < 0.9) {
                std::cout << " *** BIASED ***";
            }
            std::cout << std::endl;
        }
    }
    
    void chi_square_uniformity_test(const std::vector<uint16_t>& ports) {
        std::cout << "\n📊 CHI-SQUARE UNIFORMITY TEST:" << std::endl;
        
        const int bucket_count = 256;
        std::vector<int> buckets(bucket_count, 0);
        
        for (uint16_t port : ports) {
            int bucket = port * bucket_count / 65536;
            buckets[bucket]++;
        }
        
        double expected = (double)ports.size() / bucket_count;
        double chi_square = 0.0;
        
        for (int count : buckets) {
            double diff = count - expected;
            chi_square += (diff * diff) / expected;
        }
        
        double threshold = bucket_count + 2 * std::sqrt(2 * bucket_count);
        
        std::cout << "   Chi² statistic: " << std::fixed << std::setprecision(2) << chi_square << std::endl;
        std::cout << "   Threshold (~95%): " << std::fixed << std::setprecision(2) << threshold << std::endl;
        
        if (chi_square > threshold) {
            std::cout << "   ❌ UNIFORMITY REJECTED - Distribution is biased!" << std::endl;
        } else {
            std::cout << "   ✅ Uniformity accepted - appears random" << std::endl;
        }
    }
    
    void spectral_analysis(const std::vector<uint16_t>& ports) {
        if (ports.size() < 8) return;
        
        std::cout << "\n🌈 SPECTRAL ANALYSIS:" << std::endl;
        
        // Simple DFT magnitude analysis
        size_t N = std::min(size_t(64), ports.size());
        std::vector<std::complex<double>> dft(N/2);
        
        for (size_t k = 0; k < N/2; ++k) {
            std::complex<double> sum = 0;
            for (size_t n = 0; n < N; ++n) {
                double angle = -2.0 * M_PI * k * n / N;
                sum += std::polar((double)ports[n], angle);
            }
            dft[k] = sum;
        }
        
        // Find dominant frequencies
        std::vector<std::pair<size_t, double>> freq_power;
        for (size_t k = 1; k < N/2; ++k) {  // Skip DC component
            double power = std::abs(dft[k]);
            freq_power.emplace_back(k, power);
        }
        
        std::sort(freq_power.begin(), freq_power.end(),
                 [](const auto& a, const auto& b) { return a.second > b.second; });
        
        std::cout << "   Dominant Frequencies:" << std::endl;
        for (size_t i = 0; i < std::min(size_t(5), freq_power.size()); ++i) {
            std::cout << "     Freq " << freq_power[i].first 
                      << ": Power " << std::fixed << std::setprecision(1) 
                      << freq_power[i].second << std::endl;
        }
    }
    
    // ====================== PORT PREDICTION AND EXPLOITATION ======================
    
    std::vector<PortPrediction> predict_next_ports(int count = 10) {
        std::vector<PortPrediction> predictions;
        
        if (measurements.size() < 5) {
            std::cout << "❌ Insufficient data for prediction" << std::endl;
            return predictions;
        }
        
        std::cout << "\n🔮 PORT PREDICTION ENGINE" << std::endl;
        std::cout << "=" << std::string(50, '=') << std::endl;
        
        // Method 1: Markov Chain Prediction
        auto markov_predictions = predict_using_markov_chain(count);
        predictions.insert(predictions.end(), markov_predictions.begin(), markov_predictions.end());
        
        // Method 2: Delta Pattern Prediction  
        auto delta_predictions = predict_using_delta_patterns(count);
        predictions.insert(predictions.end(), delta_predictions.begin(), delta_predictions.end());
        
        // Method 3: LFSR State Prediction
        auto lfsr_predictions = predict_using_lfsr_state(count);
        predictions.insert(predictions.end(), lfsr_predictions.begin(), lfsr_predictions.end());
        
        return predictions;
    }
    
    std::vector<PortPrediction> predict_using_markov_chain(int count) {
        std::vector<PortPrediction> predictions;
        
        // Build Markov transition table
        std::map<uint8_t, std::map<uint8_t, int>> transitions;
        
        for (size_t i = 1; i < measurements.size(); ++i) {
            uint8_t from_state = measurements[i-1].assigned_port & 0xFF;
            uint8_t to_state = measurements[i].assigned_port & 0xFF;
            transitions[from_state][to_state]++;
        }
        
        // Start from last observed port
        uint16_t current_port = measurements.back().assigned_port;
        uint8_t current_state = current_port & 0xFF;
        
        std::cout << "🔗 Markov Chain Predictions:" << std::endl;
        
        for (int i = 0; i < count; ++i) {
            if (transitions.find(current_state) != transitions.end()) {
                // Find most probable next state
                int max_count = 0;
                uint8_t next_state = 0;
                int total_transitions = 0;
                
                for (const auto& [next, count] : transitions[current_state]) {
                    total_transitions += count;
                    if (count > max_count) {
                        max_count = count;
                        next_state = next;
                    }
                }
                
                if (max_count > 0) {
                    double confidence = (double)max_count / total_transitions;
                    
                    // Reconstruct full port (keep high bytes from current)
                    uint16_t predicted_port = (current_port & 0xFF00) | next_state;
                    
                    PortPrediction pred;
                    pred.predicted_port = predicted_port;
                    pred.confidence = confidence;
                    pred.method = "Markov";
                    pred.steps_ahead = i + 1;
                    
                    predictions.push_back(pred);
                    
                    std::cout << "   Step " << (i+1) << ": Port " << predicted_port 
                              << " (confidence: " << std::fixed << std::setprecision(3) 
                              << confidence << ")" << std::endl;
                    
                    current_port = predicted_port;
                    current_state = next_state;
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        
        return predictions;
    }
    
    std::vector<PortPrediction> predict_using_delta_patterns(int count) {
        std::vector<PortPrediction> predictions;
        
        if (measurements.size() < 3) return predictions;
        
        std::cout << "\n📊 Delta Pattern Predictions:" << std::endl;
        
        // Analyze recent delta patterns
        std::vector<int32_t> recent_deltas;
        size_t start = std::max(0, (int)measurements.size() - 10);
        
        for (size_t i = start + 1; i < measurements.size(); ++i) {
            int32_t delta = (int32_t)measurements[i].assigned_port - (int32_t)measurements[i-1].assigned_port;
            recent_deltas.push_back(delta);
        }
        
        if (recent_deltas.empty()) return predictions;
        
        // Method A: Repeating delta pattern
        if (recent_deltas.size() >= 4) {
            bool pattern_found = false;
            for (size_t pattern_len = 1; pattern_len <= recent_deltas.size()/2; ++pattern_len) {
                bool is_repeating = true;
                for (size_t i = pattern_len; i < recent_deltas.size(); ++i) {
                    if (recent_deltas[i] != recent_deltas[i % pattern_len]) {
                        is_repeating = false;
                        break;
                    }
                }
                
                if (is_repeating) {
                    uint16_t current_port = measurements.back().assigned_port;
                    
                    for (int i = 0; i < count; ++i) {
                        int32_t next_delta = recent_deltas[i % pattern_len];
                        uint16_t predicted_port = (uint16_t)(current_port + next_delta);
                        
                        PortPrediction pred;
                        pred.predicted_port = predicted_port;
                        pred.confidence = 0.8;  // High confidence for repeating patterns
                        pred.method = "DeltaPattern";
                        pred.steps_ahead = i + 1;
                        
                        predictions.push_back(pred);
                        
                        std::cout << "   Step " << (i+1) << ": Port " << predicted_port 
                                  << " (delta: " << next_delta << ")" << std::endl;
                        
                        current_port = predicted_port;
                    }
                    
                    pattern_found = true;
                    break;
                }
            }
            
            if (!pattern_found) {
                // Method B: Average delta prediction
                double avg_delta = std::accumulate(recent_deltas.begin(), recent_deltas.end(), 0.0) / recent_deltas.size();
                uint16_t current_port = measurements.back().assigned_port;
                
                std::cout << "   Using average delta: " << avg_delta << std::endl;
                
                for (int i = 0; i < std::min(count, 3); ++i) {
                    uint16_t predicted_port = (uint16_t)(current_port + avg_delta * (i + 1));
                    
                    PortPrediction pred;
                    pred.predicted_port = predicted_port;
                    pred.confidence = 0.3;  // Lower confidence
                    pred.method = "AvgDelta";
                    pred.steps_ahead = i + 1;
                    
                    predictions.push_back(pred);
                    
                    std::cout << "   Step " << (i+1) << ": Port " << predicted_port << std::endl;
                }
            }
        }
        
        return predictions;
    }
    
    std::vector<PortPrediction> predict_using_lfsr_state(int count) {
        std::vector<PortPrediction> predictions;
        
        std::cout << "\n🧮 LFSR State Predictions:" << std::endl;
        
        // Convert recent ports to bit sequence
        std::vector<int> bit_sequence;
        size_t start = std::max(0, (int)measurements.size() - 20);
        
        for (size_t i = start; i < measurements.size(); ++i) {
            for (int j = 15; j >= 0; --j) {
                bit_sequence.push_back((measurements[i].assigned_port >> j) & 1);
            }
        }
        
        if (bit_sequence.size() < 32) {
            std::cout << "   Insufficient data for LFSR prediction" << std::endl;
            return predictions;
        }
        
        // Use simplified LFSR prediction
        int complexity = berlekamp_massey(bit_sequence);
        
        if (complexity < bit_sequence.size() / 3) {
            std::cout << "   LFSR complexity: " << complexity << " - attempting prediction" << std::endl;
            
            // Simple prediction: assume XOR of last few bits
            for (int i = 0; i < std::min(count, 5); ++i) {
                // Simplified LFSR: XOR last 4 bits
                int next_bit = 0;
                if (bit_sequence.size() >= 4) {
                    next_bit = bit_sequence[bit_sequence.size()-1] ^ 
                               bit_sequence[bit_sequence.size()-2] ^
                               bit_sequence[bit_sequence.size()-3] ^ 
                               bit_sequence[bit_sequence.size()-4];
                }
                
                bit_sequence.push_back(next_bit);
                
                // Convert last 16 bits to port
                if (bit_sequence.size() >= 16) {
                    uint16_t predicted_port = 0;
                    for (int j = 0; j < 16; ++j) {
                        predicted_port = (predicted_port << 1) | bit_sequence[bit_sequence.size() - 16 + j];
                    }
                    
                    PortPrediction pred;
                    pred.predicted_port = predicted_port;
                    pred.confidence = 0.5;
                    pred.method = "LFSR";
                    pred.steps_ahead = i + 1;
                    
                    predictions.push_back(pred);
                    
                    std::cout << "   Step " << (i+1) << ": Port " << predicted_port << std::endl;
                }
            }
        } else {
            std::cout << "   High LFSR complexity - no clear pattern" << std::endl;
        }
        
        return predictions;
    }
    
    bool execute_targeted_port_manipulation(uint16_t target_port, int max_attempts = 50) {
        std::cout << "\n🎯 TARGETED PORT MANIPULATION" << std::endl;
        std::cout << "=" << std::string(50, '=') << std::endl;
        std::cout << "🎯 Target Port: " << target_port << std::endl;
        std::cout << "🔄 Max Attempts: " << max_attempts << std::endl;
        
        // First, predict what ports we'll get with current strategy
        auto predictions = predict_next_ports(max_attempts);
        
        // Check if target port is in predictions
        for (const auto& pred : predictions) {
            if (pred.predicted_port == target_port) {
                std::cout << "🎉 TARGET PORT PREDICTED!" << std::endl;
                std::cout << "   Method: " << pred.method << std::endl;
                std::cout << "   Steps ahead: " << pred.steps_ahead << std::endl;
                std::cout << "   Confidence: " << pred.confidence << std::endl;
                
                // Execute the exact number of requests needed
                return execute_precise_sequence_to_target(target_port, pred.steps_ahead);
            }
        }
        
        // If not in direct predictions, try brute force with pattern awareness
        std::cout << "⚠️  Target port not in direct predictions" << std::endl;
        std::cout << "🔄 Attempting pattern-guided brute force..." << std::endl;
        
        return execute_pattern_guided_search(target_port, max_attempts);
    }
    
    bool execute_precise_sequence_to_target(uint16_t target_port, int steps_needed) {
        std::cout << "\n🎯 Executing precise sequence to reach target..." << std::endl;
        
        // We need to send exactly 'steps_needed' packets to reach target
        for (int i = 0; i < steps_needed; ++i) {
            int sock = socket(AF_INET, SOCK_DGRAM, 0);
            if (sock < 0) continue;
            
            struct sockaddr_in source_addr, target_addr;
            
            // Bind to unique source port
            memset(&source_addr, 0, sizeof(source_addr));
            source_addr.sin_family = AF_INET;
            source_addr.sin_addr.s_addr = INADDR_ANY;
            source_addr.sin_port = htons(20000 + i);  // Different from analysis range
            bind(sock, (struct sockaddr*)&source_addr, sizeof(source_addr));
            
            // Target address
            memset(&target_addr, 0, sizeof(target_addr));
            target_addr.sin_family = AF_INET;
            target_addr.sin_port = htons(stun_port);
            inet_pton(AF_INET, target_stun_server.c_str(), &target_addr.sin_addr);
            
            // Send STUN request
            uint8_t buffer[20];
            uint8_t trans_id[12];
            for (int j = 0; j < 12; ++j) trans_id[j] = rand() & 0xFF;
            create_stun_binding_request(buffer, trans_id);
            
            sendto(sock, buffer, 20, 0, (struct sockaddr*)&target_addr, sizeof(target_addr));
            
            // Check response
            struct timeval timeout;
            timeout.tv_sec = 1;
            timeout.tv_usec = 0;
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            
            uint8_t response[1500];
            ssize_t bytes = recvfrom(sock, response, sizeof(response), 0, nullptr, nullptr);
            
            if (bytes >= 20) {
                uint16_t assigned_port = parse_mapped_address(response, bytes);
                std::cout << "   Step " << (i+1) << "/" << steps_needed << ": Got port " << assigned_port;
                
                if (assigned_port == target_port) {
                    std::cout << " 🎉 TARGET HIT!" << std::endl;
                    close(sock);
                    return true;
                }
                std::cout << std::endl;
            }
            
            close(sock);
        }
        
        std::cout << "❌ Target port not reached in predicted sequence" << std::endl;
        return false;
    }
    
    bool execute_pattern_guided_search(uint16_t target_port, int max_attempts) {
        std::cout << "\n🔍 Pattern-guided search for target port..." << std::endl;
        
        // Strategy: Use delta patterns to navigate toward target
        uint16_t current_best = measurements.back().assigned_port;
        int32_t distance_to_target = (int32_t)target_port - (int32_t)current_best;
        
        std::cout << "   Current port: " << current_best << std::endl;
        std::cout << "   Distance to target: " << distance_to_target << std::endl;
        
        // Analyze which deltas have been observed
        std::map<int32_t, int> delta_frequency;
        for (size_t i = 1; i < measurements.size(); ++i) {
            int32_t delta = (int32_t)measurements[i].assigned_port - (int32_t)measurements[i-1].assigned_port;
            delta_frequency[delta]++;
        }
        
        std::cout << "   Available deltas: ";
        for (const auto& [delta, freq] : delta_frequency) {
            std::cout << delta << "(" << freq << ") ";
        }
        std::cout << std::endl;
        
        // Smart delta selection: prefer deltas that get us closer to target
        std::vector<std::pair<int32_t, int>> sorted_deltas;
        for (const auto& [delta, freq] : delta_frequency) {
            sorted_deltas.push_back({delta, freq});
        }
        
        // Try to find combination of deltas that gets us close to target
        for (int attempt = 0; attempt < max_attempts; ++attempt) {
            int sock = socket(AF_INET, SOCK_DGRAM, 0);
            if (sock < 0) continue;
            
            struct sockaddr_in source_addr, target_addr;
            
            // Smart source port selection based on needed delta
            memset(&source_addr, 0, sizeof(source_addr));
            source_addr.sin_family = AF_INET;
            source_addr.sin_addr.s_addr = INADDR_ANY;
            
            // Calculate optimal delta needed
            int32_t needed_delta = distance_to_target;
            
            // Find best available delta for this attempt
            int32_t best_delta = 0;
            int32_t min_diff = INT32_MAX;
            
            for (const auto& [delta, freq] : delta_frequency) {
                int32_t diff = abs(needed_delta - delta);
                if (diff < min_diff) {
                    min_diff = diff;
                    best_delta = delta;
                }
            }
            
            // Use source port to try to trigger the best delta
            // Higher source ports tend to create positive deltas, lower negative
            uint16_t src_port;
            if (best_delta > 0) {
                src_port = 30000 + (attempt % 1000) + abs(best_delta % 5000);
            } else {
                src_port = 25000 - (attempt % 1000) - abs(best_delta % 5000);
            }
            
            source_addr.sin_port = htons(src_port);
            bind(sock, (struct sockaddr*)&source_addr, sizeof(source_addr));
            
            // Target setup
            memset(&target_addr, 0, sizeof(target_addr));
            target_addr.sin_family = AF_INET;
            target_addr.sin_port = htons(stun_port);
            inet_pton(AF_INET, target_stun_server.c_str(), &target_addr.sin_addr);
            
            // Send request
            uint8_t buffer[20];
            uint8_t trans_id[12];
            for (int j = 0; j < 12; ++j) trans_id[j] = rand() & 0xFF;
            create_stun_binding_request(buffer, trans_id);
            
            sendto(sock, buffer, 20, 0, (struct sockaddr*)&target_addr, sizeof(target_addr));
            
            // Get response
            struct timeval timeout;
            timeout.tv_sec = 2;
            timeout.tv_usec = 0;
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            
            uint8_t response[1500];
            ssize_t bytes = recvfrom(sock, response, sizeof(response), 0, nullptr, nullptr);
            
            if (bytes >= 20) {
                uint16_t assigned_port = parse_mapped_address(response, bytes);
                int32_t new_distance = abs((int32_t)target_port - (int32_t)assigned_port);
                
                std::cout << "   Attempt " << (attempt+1) << ": Port " << assigned_port 
                          << " (distance: " << new_distance << ")";
                
                if (assigned_port == target_port) {
                    std::cout << " 🎉 TARGET ACHIEVED!" << std::endl;
                    close(sock);
                    return true;
                }
                
                if (new_distance < abs(distance_to_target)) {
                    std::cout << " ✅ Getting closer!";
                    current_best = assigned_port;
                    distance_to_target = (int32_t)target_port - (int32_t)assigned_port;
                }
                
                std::cout << std::endl;
            }
            
            close(sock);
        }
        
        std::cout << "❌ Target port not reached within " << max_attempts << " attempts" << std::endl;
        std::cout << "   Best achieved: " << current_best << " (distance: " << abs(distance_to_target) << ")" << std::endl;
        
        return false;
    }
    
    void save_results_to_file() {
        std::string filename = "nat_analysis_results_" + 
                              std::to_string(std::chrono::duration_cast<std::chrono::seconds>(
                                  std::chrono::system_clock::now().time_since_epoch()).count()) + ".txt";
        
        std::ofstream file(filename);
        if (file.is_open()) {
            file << "NAT Pattern Analysis Results\n";
            file << "===========================\n\n";
            file << "Timestamp: " << std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count() << "\n";
            file << "Measurements: " << measurements.size() << "\n";
            file << "Target: " << target_stun_server << ":" << stun_port << "\n\n";
            
            file << "Port Sequence:\n";
            for (size_t i = 0; i < measurements.size(); ++i) {
                file << measurements[i].assigned_port;
                if (i < measurements.size() - 1) file << ",";
                if ((i + 1) % 16 == 0) file << "\n";
            }
            file << "\n\n";
            
            file << "Raw Data (port timestamp_us sequence_number):\n";
            for (const auto& m : measurements) {
                file << m.assigned_port << " " << m.timestamp_us << " " << m.sequence_number << "\n";
            }
            
            file.close();
            std::cout << "\n💾 Results saved to: " << filename << std::endl;
        }
    }
};

int main(int argc, char* argv[]) {
    std::cout << "🚀 Advanced NAT Pattern Analyzer & Port Manipulator v3.0" << std::endl;
    std::cout << "High-Performance Analysis + Predictive Port Exploitation" << std::endl;
    std::cout << "=" << std::string(60, '=') << std::endl;
    
    std::string stun_server = "stun.l.google.com";
    int packet_count = 100;
    uint16_t target_port = 0;
    std::string mode = "analyze";
    
    // Parse command line arguments
    if (argc > 1) {
        stun_server = argv[1];
    }
    if (argc > 2) {
        packet_count = std::atoi(argv[2]);
    }
    if (argc > 3) {
        std::string arg3 = argv[3];
        if (arg3 == "predict") {
            mode = "predict";
        } else if (arg3.substr(0, 6) == "target") {
            mode = "target";
            if (arg3.length() > 7) {
                target_port = std::atoi(arg3.substr(7).c_str());
            }
        } else {
            target_port = std::atoi(arg3.c_str());
            if (target_port > 0) mode = "target";
        }
    }
    
    std::cout << "📊 Configuration:" << std::endl;
    std::cout << "   STUN Server: " << stun_server << std::endl;
    std::cout << "   Analysis Packets: " << packet_count << std::endl;
    std::cout << "   Mode: " << mode << std::endl;
    if (mode == "target") {
        std::cout << "   Target Port: " << target_port << std::endl;
    }
    std::cout << std::endl;
    
    if (mode != "target" && argc <= 3) {
        std::cout << "💡 Usage modes:" << std::endl;
        std::cout << "   ./analyzer [server] [packets]              - Analysis only" << std::endl;
        std::cout << "   ./analyzer [server] [packets] predict      - Analysis + Prediction" << std::endl;
        std::cout << "   ./analyzer [server] [packets] [target_port] - Analysis + Target port attack" << std::endl;
        std::cout << "   ./analyzer [server] [packets] target:12345 - Analysis + Target port attack" << std::endl;
        std::cout << std::endl;
    }
    
    // Initialize analyzer
    AdvancedNATAnalyzer analyzer(stun_server);
    
    // Phase 1: Execute measurement campaign for pattern learning
    std::cout << "🔍 PHASE 1: PATTERN LEARNING" << std::endl;
    std::cout << "=" << std::string(40, '-') << std::endl;
    if (!analyzer.execute_high_performance_burst(packet_count)) {
        std::cerr << "❌ Failed to execute measurement burst" << std::endl;
        return 1;
    }
    
    // Phase 2: Run comprehensive pattern analysis
    std::cout << "🧠 PHASE 2: PATTERN ANALYSIS" << std::endl;
    std::cout << "=" << std::string(40, '-') << std::endl;
    analyzer.run_comprehensive_analysis();
    
    // Phase 3: Prediction and/or exploitation
    if (mode == "predict" || mode == "target") {
        std::cout << "🎯 PHASE 3: PREDICTIVE EXPLOITATION" << std::endl;
        std::cout << "=" << std::string(40, '-') << std::endl;
        
        // Generate predictions
        auto predictions = analyzer.predict_next_ports(20);
        
        if (predictions.empty()) {
            std::cout << "❌ No predictions available" << std::endl;
        } else {
            std::cout << "\n📋 PREDICTION SUMMARY:" << std::endl;
            std::cout << "=" << std::string(30, '-') << std::endl;
            
            // Group predictions by method
            std::map<std::string, std::vector<PortPrediction>> grouped_predictions;
            for (const auto& pred : predictions) {
                grouped_predictions[pred.method].push_back(pred);
            }
            
            for (const auto& [method, preds] : grouped_predictions) {
                std::cout << "\n🔮 " << method << " Method:" << std::endl;
                for (const auto& pred : preds) {
                    std::cout << "   Step +" << pred.steps_ahead << ": Port " 
                              << pred.predicted_port << " (conf: " 
                              << std::fixed << std::setprecision(2) 
                              << pred.confidence << ")" << std::endl;
                }
            }
            
            // Phase 4: Target port attack if requested
            if (mode == "target" && target_port > 0) {
                std::cout << "\n⚔️  PHASE 4: TARGET PORT ATTACK" << std::endl;
                std::cout << "=" << std::string(40, '-') << std::endl;
                
                bool success = analyzer.execute_targeted_port_manipulation(target_port, 50);
                
                if (success) {
                    std::cout << "\n🎉 SUCCESS! Target port " << target_port << " achieved!" << std::endl;
                    std::cout << "🔓 NAT port manipulation successful!" << std::endl;
                } else {
                    std::cout << "\n⚠️  Target port attack incomplete" << std::endl;
                    std::cout << "💡 Try different target port or increase attempts" << std::endl;
                }
            }
        }
    }
    
    std::cout << "\n✅ All phases complete!" << std::endl;
    std::cout << "Check output files for detailed results." << std::endl;
    
    return 0;
}
