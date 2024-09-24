#include <iostream>
#include <vector>
#include <cmath>
#include <iomanip> 
#include <cstdint> 
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



/*#########################################################################################
###################################### ORAN Section #######################################
##########################################################################################*/

/*##################################################################
############ Calculate the number of packets per symbol ############
###################################################################*/

int calculatePacketsPerSymbol(uint16_t MaxNrb, uint16_t NrbPerPacket) {
    return std::ceil(static_cast<double>(MaxNrb) / NrbPerPacket);
}

/*##################################################################
############# calculate the number of slots per frame ##############
###################################################################*/

int calculateSlotsPerFrame(uint8_t SC) {
    switch (SC) {
        case 15:
            return 10; 
        case 30:
            return 20; 
        case 60:
            return 40; 
        default:
            return 0;  
    }
}

/*##################################################################
################ Generate the ORAN User Plane Header ###############
###################################################################*/

std::vector<uint8_t> generateORANHeader(uint8_t frameID, uint8_t subframeID, uint8_t slotID, uint8_t symbolID, uint16_t MaxNrb) {
    std::vector<uint8_t> header(8, 0x00); // Initialize an 8-byte header with 0s

    header[0] = 0x00;
    header[1] = ((frameID & 0x0F) << 4) | (subframeID & 0x0F);
    header[2] = (slotID & 0x3F);   
    header[3] = ((symbolID & 0x3F) << 2); 
    header[4] = 0x00; 
    header[5] = 0x10; 
    header[6] = 0x08; 
    header[7] = MaxNrb & 0xFF;
    if (MaxNrb == 273) header[7] = 0 & 0xFF;

    return header;
}

/*##################################################################
################## Reading the IQ samples from file ################
###################################################################*/

std::vector<uint8_t> readPayloadFromFile(const std::string &filename, int payloadSize) {
    std::vector<uint8_t> payload;
    std::ifstream file(filename);
    std::string line;
    int value;
    
    if (file.is_open()) {
        while (std::getline(file, line) && payload.size() < payloadSize) {
            std::istringstream iss(line);
            while (iss >> value) {
                if (value < -128 || value > 127) {
                    std::cerr << "Invalid value in file: " << value << "\n";
                    continue;
                }
                payload.push_back(static_cast<uint8_t>(value));
                if (payload.size() >= payloadSize) {
                    break;
                }
            }
        }
        file.close();
    } else {
        std::cerr << "Unable to open file: " << filename << "\n";
    }

    return payload;
}

/*##########################################################################################
###################################### eCPRI Section #######################################
############################################################################################*/

/*##############################################
################## eCPRI Header ################
###############################################*/

// Structure for eCPRI Header (total 8 bytes)
struct EcpriHeader {
    uint8_t version_reserved_concatination; // 4 bits version, 3 bits reserved, 1 bit concatenation
    uint8_t message_type;                   // 1 byte message type
    uint16_t payload_size;                  // 2 bytes payload size
    uint16_t rtc_pc;                        // 2 bytes RTC_PC (fixed as 0x0000)
    uint16_t seq_id;                        // 2 bytes Sequence ID
};

/*##############################################
########## Generate the eCPRI Header ###########
###############################################*/

EcpriHeader createEcpriHeader(uint8_t messageType, uint16_t payloadSize, uint16_t seqID) {
    EcpriHeader header;
    header.version_reserved_concatination = 0x00; // 4 bits version set to 0x1, rest are 0
    header.message_type = messageType;                  // Set message type
    header.payload_size = payloadSize;                  // Set payload size directly
    header.rtc_pc = 0x0000;                             // Fixed 0x0000 for rtc_pc
    header.seq_id = seqID;                              // Sequence ID directly
    
    return header;
}

/*##############################################
########## Generate the eCPRI packets ##########
###############################################*/

std::vector<std::vector<uint8_t>> generateEcpriPackets(const std::vector<uint8_t>& payload, uint16_t payloadSize) {
    int seqID = 0;
    size_t totalPayloadSize = payload.size();
    size_t offset = 0;

    std::vector<std::vector<uint8_t>> allPackets; 

    while (offset < totalPayloadSize) {
        size_t currentPayloadSize = std::min(static_cast<size_t>(payloadSize), totalPayloadSize - offset);
        EcpriHeader header = createEcpriHeader(0x00, currentPayloadSize, seqID);
        std::vector<uint8_t> packet;

        packet.push_back(header.version_reserved_concatination);
        packet.push_back(header.message_type);
        packet.push_back(static_cast<uint8_t>(header.payload_size >> 8)); // High byte
        packet.push_back(static_cast<uint8_t>(header.payload_size & 0xFF)); // Low byte
        packet.push_back(static_cast<uint8_t>(header.rtc_pc >> 8)); // High byte
        packet.push_back(static_cast<uint8_t>(header.rtc_pc & 0xFF)); // Low byte
        packet.push_back(static_cast<uint8_t>(header.seq_id >> 8)); // High byte
        packet.push_back(static_cast<uint8_t>(header.seq_id & 0xFF)); // Low byte

        for (size_t i = 0; i < currentPayloadSize; i++) {
            packet.push_back(payload[offset + i]);
        }

        allPackets.push_back(packet);
        offset += currentPayloadSize;

        if (seqID != 255)
            seqID++; 
        else
            seqID = 0;
    }

    return allPackets;
}

/*##############################################
########### Display eCPRI packets  #############
###############################################*/

void displayPackets(const std::vector<std::vector<uint8_t>>& packets) {
    for (size_t i = 0; i < packets.size(); ++i) {
        const std::vector<uint8_t>& packet = packets[i];

        // Display packet number
        std::cout << "eCPRI Packet " << std::dec << i + 1 << ":\n";

        // Display header (first 8 bytes)
        std::cout << "Header: ";
        for (size_t j = 0; j < 8; ++j) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(packet[j]) << " ";
        }
        std::cout << std::endl;

        // Display payload (remaining bytes)
        std::cout << "Payload: ";
        for (size_t j = 8; j < packet.size(); ++j) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(packet[j]) << " ";
        }
        std::cout << std::endl;
        std::cout << "\n ";
    }
}

/*##############################################
####### Concatinating the eCPRI Packets  ########
###############################################*/

std::vector<uint8_t> flattenPackets(const std::vector<std::vector<uint8_t>>& packets) {
    std::vector<uint8_t> flatVector;
    for (const auto& packet : packets) {
        flatVector.insert(flatVector.end(), packet.begin(), packet.end());
    }
    return flatVector;
}

/*##########################################################################################
##################################### Ethernet Section ######################################
############################################################################################*/

/*##########################################
############ IFGs Generation ###############
##########################################*/

void sendIFGsOneByteAtATime(int no_ifgs) {
    const std::vector<uint8_t> ifgBytes = {0x07, 0x07, 0x07, 0x07};
    size_t bytesDisplayed = 0;
    size_t bytesDisplayed_total = 0;

    while (bytesDisplayed_total != no_ifgs) {
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
    size_t totalBits = data.size() * 8; 

    for (size_t i = 0; i < totalBits + 32; i++) {
        
        uint8_t currentBit;
        if (i < totalBits) {
            size_t byteIndex = i / 8;
            size_t bitIndex = 7 - (i % 8); 
            currentBit = (data[byteIndex] >> bitIndex) & 1;
        } else {
            currentBit = 0;
        }

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
                              const std::vector<uint8_t>& payloadBytes,
                              const int& Mini_ifgs) {
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
    const std::vector<uint8_t> ifgBytes (Mini_ifgs, 0x07);
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


/*#####################################################################
############################ Main Program  #############################
#######################################################################*/

int main() {
    
    //############ Get Input Parameters ############//
    uint16_t SC;                  // ORAN.SC (Subcarrier Spacing)
    uint16_t MaxNrb;              // ORAN.MaxNrb
    uint16_t NrbPerPacket;        // ORAN.NrbPerPacket
    const std::vector<uint8_t> preamble = {0xFB, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55};  
    const uint8_t sfd                   = 0xD5;  // SFD 1 byte
    double LineRate;
    int MinNumOfIFGsPerPacket;
    size_t MaxPacketSize;   
    int CaptureSize_ms;    
    std::string DestAddress, SourceAddress, etherType;
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
        std::istringstream(line) >> SC;
    }

    if (std::getline(inputFile, line)) {
        std::istringstream(line) >> MaxNrb;
    }

    if (std::getline(inputFile, line)) {
        std::istringstream(line) >> NrbPerPacket;
    }

    inputFile.close();

    // Convert inputs to byte arrays
    std::vector<uint8_t> destMacBytes = hexStringToBytes(DestAddress);
    std::vector<uint8_t> srcMacBytes = hexStringToBytes(SourceAddress);

    //############## Dumping the terminal ##############//
    std::ofstream outFile("Milestone_2_output.txt");
    
    if (!outFile.is_open()) {
        std::cerr << "Error opening file!" << std::endl;
        return 1;
    }
    std::streambuf* coutbuf = std::cout.rdbuf(); 
    std::cout.rdbuf(outFile.rdbuf());  

    //############## Calculate the necessary values ##############//
    int packetsPerSymbol = calculatePacketsPerSymbol(MaxNrb, NrbPerPacket);
    int packetsPerSlot = packetsPerSymbol * 14;
    int slotsPerFrame = calculateSlotsPerFrame(SC);
    
    if (slotsPerFrame == 0) {
        std::cout << "Invalid Subcarrier Spacing entered.\n";
        return 1;
    }

    int packetsPerSubframe = packetsPerSlot * (slotsPerFrame / 10);
    int totalPackets_perFrame= packetsPerSlot * slotsPerFrame;
    int totalPackets_bits_perFrame = totalPackets_perFrame* 2 * 16 * 12 * NrbPerPacket;
    int totalPayload_bytes_perFrame = (totalPackets_bits_perFrame -  totalPackets_perFrame*64)/ 8;  
    int totalPackets_bytes_perFrame = (totalPackets_bits_perFrame) / 8;  
    
    //############## Reading payload bytes from iq_file ##############//
    std::string filename = "iq_file.txt";
    std::vector<uint8_t> totalPayload = readPayloadFromFile(filename, totalPayload_bytes_perFrame * (CaptureSize_ms / 10 ));


    //############## Generate and display each ORAN Packets (header + payload) ##############//
    int frameID = 0;
    uint8_t subframeID = 0;
    uint8_t slotID = 0;
    uint8_t symbolID = 0;
    int counter = 0;
    int packetPayloadSize = totalPayload_bytes_perFrame / totalPackets_perFrame;
    int currentPayloadIndex = 0;
    int totalPackets = totalPackets_perFrame * (CaptureSize_ms / 10 );
    std::vector<uint8_t> ORAN_Concatinating_Packets;

    std::cout << "###### Generating frame No.  " << std::dec << frameID << " ######" << ":\n\n";
    for (int i = 0; i < totalPackets; ++i) {
        std::vector<uint8_t> header = generateORANHeader(frameID, subframeID, slotID, symbolID, MaxNrb);

        std::cout << "ORAN packet " << std::dec << i + 1 << ":\n";
        std::cout << "Header: " << "\n";
        std::cout << "  First Byte: 0x" << std::setw(2) << std::setfill('0') << std::hex << (int)header[0] << "\n";
        std::cout << "  Frame ID: " << std::dec << ((header[1] >> 4) & 0x0F) << "\n";
        std::cout << "  Subframe ID: " << std::dec << (header[1] & 0x0F) << "\n";
        std::cout << "  Slot ID: " << std::dec << (int)header[2] << "\n";
        std::cout << "  Symbol ID: " << std::dec << ((header[3] >> 2) & 0x3F) << "\n";
        std::cout << "  Section ID: " << std::dec << 1 << "\n"; // Section ID is always 1
        std::cout << "  RB: " << std::dec << 0 << "\n"; // RB is always 0
        std::cout << "  symbInc: " << std::dec << 0 << "\n"; // symbInc is always 0
        std::cout << "  startPrbu: " << std::dec << 1 << "\n"; // startPrbu is always 1
        std::cout << "  numPrbu: " << std::dec << (int)header[7] << "\n"; // MaxNrb

        std::cout << "Payload: ";
        for (int j = currentPayloadIndex; j < currentPayloadIndex + packetPayloadSize && j < totalPayload.size(); ++j) {
            std::cout << "0x" << std::setw(2) << std::setfill('0') << std::hex << (int)totalPayload[j] << " ";
        }
        std::cout << std::dec << "\n\n";

        ORAN_Concatinating_Packets.insert(ORAN_Concatinating_Packets.end(), header.begin(), header.end());
        ORAN_Concatinating_Packets.insert(ORAN_Concatinating_Packets.end(), totalPayload.begin() + currentPayloadIndex, totalPayload.begin() + currentPayloadIndex + packetPayloadSize);

        currentPayloadIndex += packetPayloadSize;

        counter += 1;
        if (counter == packetsPerSymbol)  {
            symbolID += 1;
            counter = 0;
            }

        if (symbolID == 14) {   
            symbolID = 0;
            slotID = slotID + 1;
            if (slotID == (slotsPerFrame / 10)) { 
                slotID = 0;
                subframeID = subframeID + 1;
                if (subframeID == 10) { 
                    subframeID = 0;
                    frameID = frameID + 1;
                    if (frameID < CaptureSize_ms/10) {
                        std::cout << "###### Generating frame No.  " << std::dec << frameID << " ######" << ":\n\n"; 
                    }
                }
            }
        }
        
    }

    //############## Summary of the ORAN Packets ##############//
    std::cout << "\n===== Summary =====\n";
    std::cout << "ORAN.Frames: " << std::dec << (CaptureSize_ms/10) << "\n";
    std::cout << "ORAN.MaxNrb: " << std::dec << MaxNrb << "\n";
    std::cout << "ORAN.SC: " << std::dec << (int)SC << "\n";
    std::cout << "ORAN.Slots per frame: " << std::dec << (int)slotsPerFrame << "\n";
    std::cout << "ORAN.NrbPerPacket: " << std::dec << NrbPerPacket << "\n";
    std::cout << "No. ORAN Packets per symbol: " << std::dec << packetsPerSymbol << "\n";
    std::cout << "No. ORAN Packets per slot: " << std::dec << packetsPerSlot << "\n";
    std::cout << "ORAN.Packets_Per_sub_frame: " << std::dec << packetsPerSubframe << "\n";
    std::cout << "ORAN.TotalPackets Per frame: " << std::dec << totalPackets_perFrame<< "\n";
    std::cout << "ORAN.TotalPackets: " << std::dec << totalPackets << "\n";
    std::cout << "ORAN.Payload Size (bytes): " << (totalPayload_bytes_perFrame*(CaptureSize_ms/10)) << "\n";
    std::cout << "ORAN.Total Packets Size (bytes): " << (totalPackets_bytes_perFrame*(CaptureSize_ms/10)) << "\n";


    //############## Generate and display each eCPRI Packets (header + payload) ##############//
    std::cout << std::dec << "\n";
    std::cout << "*****************  Generating eCPRI Packets ***************** " << "\n";
    std::cout << std::dec << "\n";
    std::vector<std::vector<uint8_t>> ecpriPackets = generateEcpriPackets(ORAN_Concatinating_Packets, (totalPackets_bytes_perFrame/totalPackets_perFrame));
    displayPackets(ecpriPackets);
    std::vector<uint8_t> eCPRI_Concatinating_Packets = flattenPackets(ecpriPackets);

    //############## Summary of the eCPRI Packets ##############//
    std::cout << "\n===== Summary =====\n";
    std::cout << "eCPRI. TotalPackets: " << std::dec << totalPackets<< "\n";
    std::cout << "eCPRI. Total Packets Size (bytes): " << eCPRI_Concatinating_Packets.size() << "\n";

    //############## Generate and display each Ethernet Packets (header + payload) ##############//
    // Ethernet Calculations
    float CaptureSize_us = CaptureSize_ms * 1000;
    size_t CaptureSize_totalBytes = std::ceil ((CaptureSize_us * (LineRate / 1000000)) / 8 );
    size_t ifgsBytes_total = std::ceil(CaptureSize_totalBytes - (eCPRI_Concatinating_Packets.size() + totalPackets*26 + MinNumOfIFGsPerPacket));
    int index = 0;
    int packetCount = 0;

    while (packetCount != totalPackets ) { 

            std::vector<uint8_t> packetBytes (eCPRI_Concatinating_Packets.begin() + index, eCPRI_Concatinating_Packets.begin() + index + (eCPRI_Concatinating_Packets.size()/totalPackets));
            // Construct and display the frame
            std::cout << std::dec << "Constructing and displaying Packet " << (packetCount + 1) << ":" << std::endl;
            constructAndDisplayFrame(preamble, sfd, destMacBytes, srcMacBytes, etherTypeBytes, packetBytes, MinNumOfIFGsPerPacket);
            ++packetCount;
            index = index + (eCPRI_Concatinating_Packets.size()/totalPackets);

    }

    // Simulate sending IFG bytes for the rest of capture size
    std::cout << "Sending IFG bytes for the rest capture size time " << std::endl;
    sendIFGsOneByteAtATime(ifgsBytes_total);


    //############## Summary of the Ethernet Packets ##############//
    std::cout << "\n===== Summary =====\n";
    std::cout << "Total Bytes in the Capture Size: "<< std::dec << CaptureSize_totalBytes << std::endl;
    std::cout << "Total Bytes of The EthernetPackets sent the Capture Size: "<< std::dec <<(CaptureSize_totalBytes -  ifgsBytes_total) << std::endl;
    std::cout << "Total IFG Bytes sent for the rest Capture Size: "<< std::dec << ifgsBytes_total << std::endl ;
    std::cout << "Total Ethernet Packets Sent: " << packetCount << std::endl ;


    std::cout.rdbuf(coutbuf);
    outFile.close();
    return 0;
}
