using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace PacketSniffer
{
    internal class Program
    {
        // Enum định nghĩa các loại giao thức
        enum Protocol
        {
            ICMP = 1,
            TCP = 6,
            UDP = 17,
            IPv6 = 41,
            IGMP = 2,
            GRE = 47,
            ESP = 50,
            AH = 51,
            EIGRP = 88,
            OSPF = 89,
            UNKNOWN = 255
        }
        static void Main(string[] args)
        {
            Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);

            var hostEntry = Dns.GetHostEntry(Dns.GetHostName());
            var localAddresses = hostEntry.AddressList.Where((h) => h.AddressFamily == AddressFamily.InterNetwork).ToList();

            socket.Bind(new IPEndPoint(localAddresses[0], 0));
            socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);

            byte[] inValue = BitConverter.GetBytes(1);
            byte[] outValue = new byte[4];
            socket.IOControl(IOControlCode.ReceiveAll, inValue, outValue);

            Console.WriteLine("Start Monitoring Packet...\n_______________________________\n");

            byte[] buffer = new byte[65535];

            while (true)
            {
                int bytesRead = socket.Receive(buffer);

                if (bytesRead > 0)
                {
                    ParsePacket(buffer, bytesRead);
                }
            }
        }

        static void ParsePacket(byte[] buffer, int bytesRead)
        {
            // Địa chỉ nguồn và đích là từ byte thứ 12 đến 19 trong header của IPv4
            string sourceIp = $"{buffer[12]}.{buffer[13]}.{buffer[14]}.{buffer[15]}";
            string destinationIp = $"{buffer[16]}.{buffer[17]}.{buffer[18]}.{buffer[19]}";

            // Lấy giao thức từ byte thứ 9 trong header IPv4
            int protocol = buffer[9];
            Protocol protocolEnum = (Protocol)protocol;

            // Header của TCP bắt đầu từ byte thứ 20 (sau IPv4)
            int tcpHeaderStart = 20;

            // Cổng nguồn (Source Port) và đích (Destination Port) nằm trong 2 byte đầu của TCP/UDP header
            int sourcePort = (buffer[tcpHeaderStart] << 8) + buffer[tcpHeaderStart + 1];
            int destinationPort = (buffer[tcpHeaderStart + 2] << 8) + buffer[tcpHeaderStart + 3];

            // Sequence number (4 byte từ vị trí 4-7 của TCP header)
            uint seqNum = BitConverter.ToUInt32(buffer, tcpHeaderStart + 4);

            // Acknowledgment number (4 byte từ vị trí 8-11 của TCP header)
            uint ackNum = BitConverter.ToUInt32(buffer, tcpHeaderStart + 8);

            // Header length (lấy 4 bits đầu của byte thứ 12)
            int dataOffset = (buffer[tcpHeaderStart + 12] >> 4) * 4;

            // TCP Flags (byte thứ 13 của TCP header)
            int flags = buffer[tcpHeaderStart + 13];
            string tcpFlagsHex = BitConverter.ToString(buffer, tcpHeaderStart + 13, 1);

            // Window size (2 byte, từ vị trí 14-15 của TCP header)
            int windowSize = (buffer[tcpHeaderStart + 14] << 8) + buffer[tcpHeaderStart + 15];

            // MSS (Maximum Segment Size) option, nếu tồn tại (thường nằm sau phần fixed header)
            string options = "No options";
            if (dataOffset > 20)  // Nếu header dài hơn 20 bytes, nghĩa là có options
            {
                int optionsStart = tcpHeaderStart + 20;
                options = BitConverter.ToString(buffer, optionsStart, dataOffset - 20);
            }

            // Lấy phần payload (dữ liệu) từ sau TCP header
            int payloadStart = tcpHeaderStart + dataOffset; // Vị trí bắt đầu của payload
            int payloadLength = bytesRead - payloadStart;   // Độ dài của phần dữ liệu
            byte[] payload = new byte[payloadLength];

            if (payloadLength > 0)
            {
                Array.Copy(buffer, payloadStart, payload, 0, payloadLength);
            }

            int length = bytesRead;

            // Hiển thị thông tin gói tin
            Console.WriteLine($"Source: {sourceIp}:{sourcePort} -> Destination: {destinationIp}:{destinationPort}");
            Console.WriteLine($"Protocol: {(Protocol)protocolEnum} (numeric: {protocol})");
            Console.WriteLine("Length: " + length + " - "+   " bytes");
            Console.WriteLine($"Sequence Number: {seqNum}");
            Console.WriteLine($"Acknowledgment Number: {ackNum}");
            Console.WriteLine($"TCP Flags (binary): {Convert.ToString(flags, 2).PadLeft(8, '0')} (hex: {tcpFlagsHex})");
            Console.WriteLine($"Window Size: {windowSize}");
            Console.WriteLine($"Options: {options}");
            Console.WriteLine($"Payload Length: {payloadLength} bytes");

            // Nếu có dữ liệu payload thì hiển thị
            if (payloadLength > 0)
            {
                string payloadHex = BitConverter.ToString(payload); // Hiển thị payload dưới dạng hex
                Console.WriteLine($"Payload (hex): {payloadHex}");
            }

            Console.WriteLine(new string('-', 50));
        }


    }
}
