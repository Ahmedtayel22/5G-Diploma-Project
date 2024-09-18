#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdint>
#include <fstream>
#include <thread>
#include <chrono>
#include <cmath>



/*##############################################
IMPORTANT NOTES: 
[1] Use my config.txt with your desired values NOT param.text file.
[2] I used a 32-CRC with inital value = 0x00000000 and Polynomial = 0x814141AB,
 I validated the CRC using this CRC Calculator : https://crccalc.com/?crc=123456789&method=&datatype=0&outtype=0
[3] The output will be dumped into the output.txt file 
################################################*/



/*##########################################
############ IFGs Generation ###############
##########################################*/
void sendIFGsOneByteAtATime(int no_ifgs) {
    const std::vector<uint8_t> ifgBytes = {0x07, 0x07, 0x07, 0x07};
    size_t bytesDisplayed = 0;
    size_t bytesDisplayed_total = 0;

    while (bytesDisplayed_total != no_ifgs) {
        // Display the next IFG byte in sequence, aligned properly
        std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)ifgBytes[bytesDisplayed] << " ";
        bytesDisplayed++;
        if (bytesDisplayed == 4) {
            std::cout << std::endl;
            bytesDisplayed = 0;
        }
        bytesDisplayed_total = bytesDisplayed_total + 1;
    }

    if (bytesDisplayed > 0) {
        std::cout << std::endl;
    }
}


/*##########################################
############ CRC Computation ###############
##########################################*/

uint32_t computeCustomCRC32(const std::vector<uint8_t>& data) {
    uint32_t crc = 0x00000000;
    const uint32_t polynomial = 0x814141AB;
    size_t totalBits = data.size() * 8; // Appending 32 zeros to start the division operation

    // Get the corresponding bit 
    for (size_t i = 0; i < totalBits + 32; i++) {
        
        uint8_t currentBit;
        if (i < totalBits) {
            size_t byteIndex = i / 8;
            size_t bitIndex = 7 - (i % 8); // Work from MSB to LSB
            currentBit = (data[byteIndex] >> bitIndex) & 1;
        } else {
            currentBit = 0;
        }

    // CRC Operation
        if ((crc & 0x80000000) != 0) {
            crc = (crc << 1) ^ polynomial;
        } else {
            crc <<= 1;
        }

        crc ^= currentBit;
    }

    return crc;
}


/*##############################################################################
############ Convert a string of hexadecimal characters to bytes ###############
##############################################################################*/

// Convert a string of hexadecimal characters to bytes
std::vector<uint8_t> hexStringToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t) strtol(byteString.c_str(), nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}


/*###################################################
############ 4-Bytes Alligned display ###############
####################################################*/

void displayFrameIn4ByteGroups(const std::vector<uint8_t>& frame) {
    size_t size = frame.size();
    size_t i = 0;

    // Display in groups of 4 bytes
    while (i < size) {
        for (size_t j = 0; j < 4 && i < size; ++j, ++i) {
            std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)frame[i] << " ";
        }
        std::cout << std::endl;
    }
}


/*######################################################
############ Ethernet Frame Constructing ###############
#######################################################*/

void constructAndDisplayFrame(const std::vector<uint8_t>& preamble,
                              const uint8_t sfd,
                              const std::vector<uint8_t>& destMacBytes,
                              const std::vector<uint8_t>& srcMacBytes,
                              const std::vector<uint8_t>& etherTypeBytes,
                              const std::vector<uint8_t>& payloadBytes) {
    std::vector<uint8_t> ethernetFrame;

    ethernetFrame.insert(ethernetFrame.end(), preamble.begin(), preamble.end());

    ethernetFrame.push_back(sfd);

    ethernetFrame.insert(ethernetFrame.end(), destMacBytes.begin(), destMacBytes.end());

    ethernetFrame.insert(ethernetFrame.end(), srcMacBytes.begin(), srcMacBytes.end());

    ethernetFrame.insert(ethernetFrame.end(), etherTypeBytes.begin(), etherTypeBytes.end());

    ethernetFrame.insert(ethernetFrame.end(), payloadBytes.begin(), payloadBytes.end());

    // Step 1: Compute CRC for the payload and add it to the frame
    uint32_t payloadCrc = computeCustomCRC32(payloadBytes);  
    ethernetFrame.push_back((payloadCrc >> 24) & 0xFF);
    ethernetFrame.push_back((payloadCrc >> 16) & 0xFF);
    ethernetFrame.push_back((payloadCrc >> 8) & 0xFF);
    ethernetFrame.push_back(payloadCrc & 0xFF);

    // Step 2: Add 12 IFG bytes
    const std::vector<uint8_t> ifgBytes = {0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07};
    ethernetFrame.insert(ethernetFrame.end(), ifgBytes.begin(), ifgBytes.end());

    // Step 3: Check for 4-byte alignment
    size_t frameSize = ethernetFrame.size();
    size_t remainder = frameSize % 4;
    if (remainder != 0) {
        size_t padding = 4 - remainder;
        ethernetFrame.insert(ethernetFrame.end(), padding, 0x07);  // Insert more IFG bytes to align
    }

    // Display the Ethernet frame in 4-byte groups
    std::cout << "Ethernet frame in 4-byte groups (padded with IFG=0x07 and aligned): " << std::endl;
    displayFrameIn4ByteGroups(ethernetFrame);
}

int main() {


    // Dumping the terminal into output.txt file
    std::ofstream outFile("output.txt");
    
    if (!outFile.is_open()) {
        std::cerr << "Error opening file!" << std::endl;
        return 1;
    }
    std::streambuf* coutbuf = std::cout.rdbuf(); 
    std::cout.rdbuf(outFile.rdbuf());          


    // Decleration of the parameters and Ethernet frame fields
    const std::vector<uint8_t> preamble = {0xFB, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55};  
    const uint8_t sfd                   = 0xD5;  // SFD 1 byte
    double LineRate;
    int MinNumOfIFGsPerPacket;
    size_t MaxPacketSize;    // Packet Size in bytes
    int CaptureSize_ms;    // Generation time in sec
    int BurstSize;    // Burst Size in packets
    int BurstPeriodicity_us;    // Burst Periodicity in sec
    std::string DestAddress, SourceAddress , etherType, payload;
    const std::vector<uint8_t> etherTypeBytes = {0xDD, 0xDD};
    std::string line;

    
    std::ifstream inputFile ("config.txt");
    if (!inputFile.is_open()) {
        std::cerr << "Error: Could not open input file." << std::endl;
        return -1;
    }

    if (std::getline(inputFile, line)) {
        std::istringstream(line) >> LineRate;
    }

    if (std::getline(inputFile, line)) {
        std::istringstream(line) >> CaptureSize_ms;
    }

    if (std::getline(inputFile, line)) {
        std::istringstream(line) >> MinNumOfIFGsPerPacket;
    }

    std::getline(inputFile, DestAddress);
    std::getline(inputFile, SourceAddress);

    if (std::getline(inputFile, line)) {
        std::istringstream(line) >> MaxPacketSize;
    }

    if (std::getline(inputFile, line)) {
        std::istringstream(line) >> BurstSize;
    }

    if (std::getline(inputFile, line)) {
        std::istringstream(line) >> BurstPeriodicity_us;
    }

    inputFile.close();

    // Convert inputs to byte arrays
    std::vector<uint8_t> destMacBytes = hexStringToBytes(DestAddress);
    std::vector<uint8_t> srcMacBytes = hexStringToBytes(SourceAddress);
    
    // Total packets calculations
    float CaptureSize_us = CaptureSize_ms * 1000;
    size_t CaptureSize_totalBytes = std::ceil ((CaptureSize_us * (LineRate / 1000000)) / 8 );
    size_t noOfbursts = (CaptureSize_us)/BurstPeriodicity_us;
    float packet_time_us =  ((1512*8) / (LineRate / 1000000));
    float ifg_interval_us =  (BurstPeriodicity_us - (packet_time_us * BurstSize));
    size_t ifgsBytes_perBurst = std::ceil((LineRate/8000000) * ifg_interval_us);
    size_t ifgsBytes_total = std::ceil(ifgsBytes_perBurst*noOfbursts);
    size_t CaptureSize_packetsBytes = std::ceil (CaptureSize_totalBytes - ifgsBytes_total);
    size_t total_packets = std::ceil (CaptureSize_packetsBytes / 1512);
    size_t CaptureSize_payloadBytes = std::ceil (total_packets*(1500-26));


/*
    std::cout << packet_time_us << std::endl ;
    std::cout << ifg_interval_us << std::endl ;
    std::cout << CaptureSize_packetsBytes << std::endl ;
    std::cout << CaptureSize_payloadBytes << std::endl ;
    std::cout << total_packets << std::endl ;
    std::cout << ifgsBytes_total << std::endl ;
    std::cout << noOfbursts << std::endl ;

*/


    int index = 0;
    int packetCount = 0;
    float countBursts = 0;
    std::vector<uint8_t> payloadBytes((CaptureSize_payloadBytes), 0x00); 
    while (countBursts != noOfbursts ) { 
        for (size_t i = 0; i < BurstSize; ++i) {
            std::vector<uint8_t> packetBytes (payloadBytes.begin() + index, payloadBytes.begin() + index + 1474);
            // Construct and display the frame
            std::cout << std::dec << "Constructing and displaying Packet " << (packetCount + 1) << ":" << std::endl;
            constructAndDisplayFrame(preamble, sfd, destMacBytes, srcMacBytes, etherTypeBytes, packetBytes);
            ++packetCount;
            index = index + 1474;
                }
            
            countBursts = countBursts + 1;
        // Simulate sending IFG bytes for the duration of the burst periodicity
        std::cout << "Sending IFG bytes withing the silet interval " << std::dec << ifg_interval_us << " microseconds..." << std::endl;

        sendIFGsOneByteAtATime(ifgsBytes_perBurst);

    }

    std::cout.rdbuf(coutbuf);
    outFile.close();

    
    return 0;
}
