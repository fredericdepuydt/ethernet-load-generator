using System;
using System.Collections.Generic;
using PcapDotNet.Base;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Arp;
using PcapDotNet.Packets.Dns;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.Gre;
using PcapDotNet.Packets.Http;
using PcapDotNet.Packets.Icmp;
using PcapDotNet.Packets.Igmp;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.IpV6;
using PcapDotNet.Packets.Transport;

namespace Application
{
    class CapturingThePacketsWithoutTheCallback
    {
        
        static PacketCommunicator Communicator;
        public static void HandlePackets()
        {
            // Retrieve the device list from the local machine
            IList<LivePacketDevice> allDevices = LivePacketDevice.AllLocalMachine;

            if (allDevices.Count == 0)
            {
                Console.WriteLine("No interfaces found! Make sure WinPcap is installed.");
                return;
            }

            // Print the list
            for (int i = 0; i != allDevices.Count; ++i)
            {
                LivePacketDevice device = allDevices[i];
                Console.Write((i + 1) + ". " + device.Name);
                if (device.Description != null)
                    Console.WriteLine(" (" + device.Description + ")");
                else
                    Console.WriteLine(" (No description available)");
            }

            int deviceIndex = 0;
            do
            {
                Console.WriteLine("Enter the interface number (1-" + allDevices.Count + "):");
                string deviceIndexString = Console.ReadLine();
                if (!int.TryParse(deviceIndexString, out deviceIndex) ||
                    deviceIndex < 1 || deviceIndex > allDevices.Count)
                {
                    deviceIndex = 0;
                }
            } while (deviceIndex == 0);

            // Take the selected adapter
            PacketDevice selectedDevice = allDevices[deviceIndex - 1];
            Communicator = selectedDevice.Open(128,                // portion of the packet to capture
                                    PacketDeviceOpenAttributes.Promiscuous, // promiscuous mode
                                    1);

            // Open the device
            String Filter = "(ether host 00:a0:45:95:01:66) or (ether host 00:a0:45:95:01:b6)";
            Communicator.SetFilter(Filter);
            Console.WriteLine("Listening on " + selectedDevice.Description + "...");
            Console.WriteLine("Filter: " + Filter);

            
            Packet receivePacket;
            Packet sendPacket;
            IpV4Address dest_IP = new IpV4Address("8.8.4.4");
            do
            {
                switch (Communicator.ReceivePacket(out receivePacket))
                {
                    case PacketCommunicatorReceiveResult.Timeout:
                        // Timeout elapsed
                        continue;
                    case PacketCommunicatorReceiveResult.Ok:
                        if (receivePacket.Buffer[34] == 8 && receivePacket.Buffer[35] == 8 && receivePacket.Buffer[36] == 8 && receivePacket.Buffer[37] == 8)
                        {
                            sendPacket = receivePacket;
                            sendPacket.Buffer[34] = 10;
                            sendPacket.Buffer[35] = 132;
                            sendPacket.Buffer[36] = 1;
                            sendPacket.Buffer[37] = 5;
                            UInt32 checksum = 0;
                            checksum += ((uint)sendPacket.Buffer[18]) * 256;
                            checksum += ((uint)sendPacket.Buffer[19]);
                            checksum += ((uint)sendPacket.Buffer[20]) * 256;
                            checksum += ((uint)sendPacket.Buffer[21]);
                            checksum += ((uint)sendPacket.Buffer[22]) * 256;
                            checksum += ((uint)sendPacket.Buffer[23]);
                            checksum += ((uint)sendPacket.Buffer[24]) * 256;
                            checksum += ((uint)sendPacket.Buffer[25]);
                            checksum += ((uint)sendPacket.Buffer[26]) * 256;
                            checksum += ((uint)sendPacket.Buffer[27]);

                            checksum += ((uint)sendPacket.Buffer[30]) * 256;
                            checksum += ((uint)sendPacket.Buffer[31]);
                            checksum += ((uint)sendPacket.Buffer[32]) * 256;
                            checksum += ((uint)sendPacket.Buffer[33]);
                            checksum += ((uint)sendPacket.Buffer[34]) * 256;
                            checksum += ((uint)sendPacket.Buffer[35]);
                            checksum += ((uint)sendPacket.Buffer[36]) * 256;
                            checksum += ((uint)sendPacket.Buffer[37]);
                            while (((checksum & 0xffff0000) >> 16) != 0)
                            {
                                checksum = ((checksum & 0xffff0000) >> 16) + (checksum & 0x0000ffff);
                            }
                            checksum = ~checksum;
                            sendPacket.Buffer[28] = (byte)((checksum & 0xff00) >> 8);
                            sendPacket.Buffer[29] = (byte)(checksum & 0x00ff);


                            sendPacket.Buffer[38] = (byte)(0xA2);
                            sendPacket.Buffer[39] = (byte)(0xE5);
                            sendPacket.Buffer[46] = (byte)((uint)(sendPacket.Buffer[46])+1);

                            checksum = 0;
                            checksum += ((uint)sendPacket.Buffer[30]) * 256;
                            checksum += ((uint)sendPacket.Buffer[31]);
                            checksum += ((uint)sendPacket.Buffer[32]) * 256;
                            checksum += ((uint)sendPacket.Buffer[33]);
                            checksum += ((uint)sendPacket.Buffer[34]) * 256;
                            checksum += ((uint)sendPacket.Buffer[35]);
                            checksum += ((uint)sendPacket.Buffer[36]) * 256;
                            checksum += ((uint)sendPacket.Buffer[37]);

                            checksum += ((uint)sendPacket.Buffer[27]);

                            checksum += ((uint)sendPacket.Buffer[38]) * 256;
                            checksum += ((uint)sendPacket.Buffer[39]);
                            checksum += ((uint)sendPacket.Buffer[40]) * 256;
                            checksum += ((uint)sendPacket.Buffer[41]);

                            checksum += ((uint)sendPacket.Buffer[42]) * 256;
                            checksum += ((uint)sendPacket.Buffer[43]);
                            checksum += ((uint)sendPacket.Buffer[42]) * 256;
                            checksum += ((uint)sendPacket.Buffer[43]);

                            int i = 46;
                            while (i < sendPacket.Buffer.Length)
                            {
                                checksum += ((uint)sendPacket.Buffer[i] * 256);
                                checksum += ((uint)sendPacket.Buffer[i+1]);
                                i = i + 2;
                            }



                            while (((checksum & 0xffff0000) >> 16) != 0)
                            {
                                checksum = ((checksum & 0xffff0000) >> 16) + (checksum & 0x0000ffff);
                            }
                            checksum = ~checksum;
                            sendPacket.Buffer[44] = (byte)((checksum & 0xff00) >> 8);
                            sendPacket.Buffer[45] = (byte)(checksum & 0x00ff);

                            Console.WriteLine("Found request DNS 8.8.8.8");
                            Communicator.SendPacket(sendPacket);
                        }
                        if (receivePacket.Buffer[34] == 8 && receivePacket.Buffer[35] == 8 && receivePacket.Buffer[36] == 4 && receivePacket.Buffer[37] == 4)
                        {
                            sendPacket = receivePacket;
                            sendPacket.Buffer[34] = 10;
                            sendPacket.Buffer[35] = 132;
                            sendPacket.Buffer[36] = 1;
                            sendPacket.Buffer[37] = 6;
                            UInt32 checksum = 0;
                            checksum += ((uint)sendPacket.Buffer[18]) * 256;
                            checksum += ((uint)sendPacket.Buffer[19]);
                            checksum += ((uint)sendPacket.Buffer[20]) * 256;
                            checksum += ((uint)sendPacket.Buffer[21]);
                            checksum += ((uint)sendPacket.Buffer[22]) * 256;
                            checksum += ((uint)sendPacket.Buffer[23]);
                            checksum += ((uint)sendPacket.Buffer[24]) * 256;
                            checksum += ((uint)sendPacket.Buffer[25]);
                            checksum += ((uint)sendPacket.Buffer[26]) * 256;
                            checksum += ((uint)sendPacket.Buffer[27]);

                            checksum += ((uint)sendPacket.Buffer[30]) * 256;
                            checksum += ((uint)sendPacket.Buffer[31]);
                            checksum += ((uint)sendPacket.Buffer[32]) * 256;
                            checksum += ((uint)sendPacket.Buffer[33]);
                            checksum += ((uint)sendPacket.Buffer[34]) * 256;
                            checksum += ((uint)sendPacket.Buffer[35]);
                            checksum += ((uint)sendPacket.Buffer[36]) * 256;
                            checksum += ((uint)sendPacket.Buffer[37]);
                            while (((checksum & 0xffff0000) >> 16) != 0){ 
                                checksum = ((checksum & 0xffff0000) >> 16) + (checksum & 0x0000ffff);
                            }
                            checksum = ~checksum;

                            sendPacket.Buffer[28] = (byte)((checksum & 0xff00) >> 8);
                            sendPacket.Buffer[29] = (byte)(checksum & 0x00ff);

                            sendPacket.Buffer[38] = (byte)(0xA2);
                            sendPacket.Buffer[39] = (byte)(0xE5);
                            sendPacket.Buffer[46] = (byte)((uint)(sendPacket.Buffer[46]) + 1);

                            checksum = 0;
                            checksum += ((uint)sendPacket.Buffer[30]) * 256;
                            checksum += ((uint)sendPacket.Buffer[31]);
                            checksum += ((uint)sendPacket.Buffer[32]) * 256;
                            checksum += ((uint)sendPacket.Buffer[33]);
                            checksum += ((uint)sendPacket.Buffer[34]) * 256;
                            checksum += ((uint)sendPacket.Buffer[35]);
                            checksum += ((uint)sendPacket.Buffer[36]) * 256;
                            checksum += ((uint)sendPacket.Buffer[37]);

                            checksum += ((uint)sendPacket.Buffer[27]);

                            checksum += ((uint)sendPacket.Buffer[38]) * 256;
                            checksum += ((uint)sendPacket.Buffer[39]);
                            checksum += ((uint)sendPacket.Buffer[40]) * 256;
                            checksum += ((uint)sendPacket.Buffer[41]);

                            checksum += ((uint)sendPacket.Buffer[42]) * 256;
                            checksum += ((uint)sendPacket.Buffer[43]);
                            checksum += ((uint)sendPacket.Buffer[42]) * 256;
                            checksum += ((uint)sendPacket.Buffer[43]);
                            int i = 46;
                            while (i < sendPacket.Buffer.Length)
                            {
                                checksum += ((uint)sendPacket.Buffer[i++] * 256);
                                checksum += ((uint)sendPacket.Buffer[i++]);
                            }



                            while (((checksum & 0xffff0000) >> 16) != 0)
                            {
                                checksum = ((checksum & 0xffff0000) >> 16) + (checksum & 0x0000ffff);
                            }
                            checksum = ~checksum;
                            sendPacket.Buffer[44] = (byte)((checksum & 0xff00) >> 8);
                            sendPacket.Buffer[45] = (byte)(checksum & 0x00ff);



                            Console.WriteLine("Found request DNS 8.8.4.4");
                            Communicator.SendPacket(sendPacket);
                        }

                        break;
                    default:
                        throw new InvalidOperationException("The result should never be reached here");
                }
            } while (true);
        }

        public static Packet BuildVLanTaggedFramePacket(int cyclecounter)
        {
            EthernetLayer ethernetLayer =
                new EthernetLayer
                {
                    Source = new MacAddress("28:63:36:88:02:52"),
                    Destination = new MacAddress("00:1b:1b:6b:6b:0e"),
                    EtherType = EthernetType.None, // Will be filled automatically.
                };

            VLanTaggedFrameLayer vLanTaggedFrameLayer =
                new VLanTaggedFrameLayer
                {
                    PriorityCodePoint = ClassOfService.InternetworkControl,
                    CanonicalFormatIndicator = false,
                    VLanIdentifier = 50,
                    EtherType = (EthernetType)34962,
                };

            PayloadLayer payloadLayer =
                new PayloadLayer
                {
                    Data = new Datagram(new byte[] { 0x80, 0x00,
                    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0xFF, 0x80, 0xFF,
                    0x80, 0x80, 0x80, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x80, 0x80,
                    Convert.ToByte((cyclecounter &  0xFF00) > 8), Convert.ToByte(cyclecounter & 0xFF), 0x35, 0x00})
                };

            PacketBuilder builder = new PacketBuilder(ethernetLayer, vLanTaggedFrameLayer, payloadLayer);

            return builder.Build(DateTime.Now);
        }
    }
}