using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
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
    public static class BuildPackets
    {
        /// <summary>
        /// This function build an Ethernet with payload packet.
        /// </summary>
        public static Packet BuildEthernetPacket()
        {
            EthernetLayer ethernetLayer =
                new EthernetLayer
                {
                    Source = new MacAddress("01:01:01:01:01:01"),
                    Destination = new MacAddress("FF:FF:FF:FF:FF:FF"),
                    EtherType = EthernetType.IpV4,
                };

            PayloadLayer payloadLayer =
                new PayloadLayer
                {
                    Data = new Datagram(Encoding.ASCII.GetBytes("hello world")),
                };

            PacketBuilder builder = new PacketBuilder(ethernetLayer, payloadLayer);

            return builder.Build(DateTime.Now);
        }

        /// <summary>
        /// This function build an ARP over Ethernet packet.
        /// </summary>
        public static Packet BuildArpPacket()
        {
            EthernetLayer ethernetLayer =
                new EthernetLayer
                {
                    Source = new MacAddress("68:05:ca:1e:94:1c"),
                    Destination = new MacAddress("FF:FF:FF:FF:FF:FF"),
                    EtherType = EthernetType.None, // Will be filled automatically.
                };

            

            ArpLayer arpLayer =
                new ArpLayer
                {
                    ProtocolType = EthernetType.IpV4,
                    Operation = ArpOperation.InverseRequest,
                    SenderHardwareAddress = new byte[] { 104, 5, 202, 30, 148, 28 }.AsReadOnly(), // 68:05:ca:1e:94:1c
                    SenderProtocolAddress = new byte[] { 10, 128, 24, 154 }.AsReadOnly(), // 1.2.3.4.
                    TargetHardwareAddress = new byte[] { 08 , 46, 95, 228, 211, 146 }.AsReadOnly(), // 04:04:04:04:04:04.
                    TargetProtocolAddress = new byte[] { 255, 255, 255, 255 }.AsReadOnly(), // 11.22.33.44.
                };

            PacketBuilder builder = new PacketBuilder(ethernetLayer, arpLayer);

            return builder.Build(DateTime.Now);
        }

        /// <summary>
        /// This function build a VLanTaggedFrame over Ethernet with payload packet.
        /// </summary>
        public static Packet BuildVLanTaggedFramePacket()
        {
            EthernetLayer ethernetLayer =
                new EthernetLayer
                {
                    Source = new MacAddress("01:01:01:01:01:01"),
                    Destination = new MacAddress("02:02:02:02:02:02"),
                    EtherType = EthernetType.None, // Will be filled automatically.
                };

            VLanTaggedFrameLayer vLanTaggedFrameLayer =
                new VLanTaggedFrameLayer
                {
                    PriorityCodePoint = ClassOfService.NetworkControl,
                    CanonicalFormatIndicator = false,
                    VLanIdentifier = 50,
                    EtherType = (EthernetType)34962,
                };

            PayloadLayer payloadLayer =
                new PayloadLayer
                {
                    Data = new Datagram(new byte[] { 0x80, 0x6B,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x10, 0x10, 0x35, 0x00})
                };

            PacketBuilder builder = new PacketBuilder(ethernetLayer, vLanTaggedFrameLayer, payloadLayer);

            return builder.Build(DateTime.Now);
        }

        public static Packet BuildProfinetFramePacket()
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
                    PriorityCodePoint = ClassOfService.NetworkControl,
                    CanonicalFormatIndicator = false,
                    VLanIdentifier = 50,
                    EtherType = (EthernetType)34962,
                };

            PayloadLayer payloadLayer =
                new PayloadLayer
                {
                    Data = new Datagram(new byte[] { 0x80, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x10, 0x40, 0x35, 0x00})
                };

            PacketBuilder builder = new PacketBuilder(ethernetLayer, vLanTaggedFrameLayer, payloadLayer);

            return builder.Build(DateTime.Now);
        }

        /// <summary>
        /// This function build an IPv4 over Ethernet with payload packet.
        /// </summary>
        public static Packet BuildIpV4Packet()
        {
            EthernetLayer ethernetLayer =
                new EthernetLayer
                {
                    Source = new MacAddress("68:05:CA:1E:94:1C"),
                    Destination = new MacAddress("90:A2:DA:0D:F7:CD"),
                    EtherType = EthernetType.None,
                };

            IpV4Layer ipV4Layer =
                new IpV4Layer
                {
                    Source = new IpV4Address("10.128.24.154"),
                    CurrentDestination = new IpV4Address("10.128.24.165"),
                    Fragmentation = IpV4Fragmentation.None,
                    HeaderChecksum = null, // Will be filled automatically.
                    Identification = 123,
                    Options = IpV4Options.None,
                    Protocol = IpV4Protocol.Udp,
                    Ttl = 100,
                    TypeOfService = 0,
                };

            PayloadLayer payloadLayer =
                new PayloadLayer
                {
                    Data = new Datagram(Encoding.ASCII.GetBytes("hello world")),
                };

            PacketBuilder builder = new PacketBuilder(ethernetLayer, ipV4Layer, payloadLayer);

            return builder.Build(DateTime.Now);
        }

        /// <summary>
        /// This function build an IPv6 over Ethernet with payload packet.
        /// </summary>
        public static Packet BuildIpV6Packet()
        {
            EthernetLayer ethernetLayer =
                new EthernetLayer
                {
                    Source = new MacAddress("68:05:CA:1E:94:1C"),
                    Destination = new MacAddress("90:A2:DA:0D:F7:CD"),
                    EtherType = EthernetType.None,
                };

            IpV6Layer ipV6Layer =
                new IpV6Layer
                {
                    Source = new IpV6Address("0123:4567:89AB:CDEF:0123:4567:89AB:CDEF"),
                    CurrentDestination = new IpV6Address("FEDC:BA98:7654:3210:FEDC:BA98:7654:3210"),
                    FlowLabel = 123,
                    HopLimit = 100,
                    NextHeader = IpV4Protocol.Udp,
                };

            PayloadLayer payloadLayer =
                new PayloadLayer
                {
                    Data = new Datagram(Encoding.ASCII.GetBytes("hello world")),
                };

            PacketBuilder builder = new PacketBuilder(ethernetLayer, ipV6Layer, payloadLayer);

            return builder.Build(DateTime.Now);
        }

        /// <summary>
        /// This function build an ICMP over IPv4 over Ethernet packet.
        /// </summary>
        public static Packet BuildIcmpPacket()
        {
            EthernetLayer ethernetLayer =
                new EthernetLayer
                {
                    Source = new MacAddress("01:01:01:01:01:01"),
                    Destination = new MacAddress("02:02:02:02:02:02"),
                    EtherType = EthernetType.None, // Will be filled automatically.
                };

            IpV4Layer ipV4Layer =
                new IpV4Layer
                {
                    Source = new IpV4Address("1.2.3.4"),
                    CurrentDestination = new IpV4Address("11.22.33.44"),
                    Fragmentation = IpV4Fragmentation.None,
                    HeaderChecksum = null, // Will be filled automatically.
                    Identification = 123,
                    Options = IpV4Options.None,
                    Protocol = null, // Will be filled automatically.
                    Ttl = 100,
                    TypeOfService = 0,
                };

            IcmpEchoLayer icmpLayer =
                new IcmpEchoLayer
                {
                    Checksum = null, // Will be filled automatically.
                    Identifier = 456,
                    SequenceNumber = 800,
                };

            PacketBuilder builder = new PacketBuilder(ethernetLayer, ipV4Layer, icmpLayer);

            return builder.Build(DateTime.Now);
        }

        /// <summary>
        /// This function build an IGMP over IPv4 over Ethernet packet.
        /// </summary>
        public static Packet BuildIgmpPacket()
        {
            EthernetLayer ethernetLayer =
                new EthernetLayer
                {
                    Source = new MacAddress("01:01:01:01:01:01"),
                    Destination = new MacAddress("02:02:02:02:02:02"),
                    EtherType = EthernetType.None, // Will be filled automatically.
                };

            IpV4Layer ipV4Layer =
                new IpV4Layer
                {
                    Source = new IpV4Address("1.2.3.4"),
                    CurrentDestination = new IpV4Address("11.22.33.44"),
                    Fragmentation = IpV4Fragmentation.None,
                    HeaderChecksum = null, // Will be filled automatically.
                    Identification = 123,
                    Options = IpV4Options.None,
                    Protocol = null, // Will be filled automatically.
                    Ttl = 100,
                    TypeOfService = 0,
                };

            IgmpQueryVersion1Layer igmpLayer =
                new IgmpQueryVersion1Layer
                {
                    GroupAddress = new IpV4Address("1.2.3.4"),
                };

            PacketBuilder builder = new PacketBuilder(ethernetLayer, ipV4Layer, igmpLayer);

            return builder.Build(DateTime.Now);
        }

        /// <summary>
        /// This function build an IPv4 over GRE over IPv4 over Ethernet packet.
        /// </summary>
        public static Packet BuildGrePacket()
        {
            EthernetLayer ethernetLayer =
                new EthernetLayer
                {
                    Source = new MacAddress("01:01:01:01:01:01"),
                    Destination = new MacAddress("02:02:02:02:02:02"),
                    EtherType = EthernetType.None, // Will be filled automatically.
                };

            IpV4Layer ipV4Layer =
                new IpV4Layer
                {
                    Source = new IpV4Address("1.2.3.4"),
                    CurrentDestination = new IpV4Address("11.22.33.44"),
                    Fragmentation = IpV4Fragmentation.None,
                    HeaderChecksum = null, // Will be filled automatically.
                    Identification = 123,
                    Options = IpV4Options.None,
                    Protocol = null, // Will be filled automatically.
                    Ttl = 100,
                    TypeOfService = 0,
                };

            GreLayer greLayer =
                new GreLayer
                {
                    Version = GreVersion.Gre,
                    ProtocolType = EthernetType.None, // Will be filled automatically.
                    RecursionControl = 0,
                    FutureUseBits = 0,
                    ChecksumPresent = true,
                    Checksum = null, // Will be filled automatically.
                    Key = null,
                    SequenceNumber = 123,
                    AcknowledgmentSequenceNumber = null,
                    RoutingOffset = null,
                    Routing = null,
                    StrictSourceRoute = false,
                };

            IpV4Layer innerIpV4Layer =
                new IpV4Layer
                {
                    Source = new IpV4Address("100.200.201.202"),
                    CurrentDestination = new IpV4Address("123.254.132.40"),
                    Fragmentation = IpV4Fragmentation.None,
                    HeaderChecksum = null, // Will be filled automatically.
                    Identification = 123,
                    Options = IpV4Options.None,
                    Protocol = IpV4Protocol.Udp,
                    Ttl = 120,
                    TypeOfService = 0,
                };

            PacketBuilder builder = new PacketBuilder(ethernetLayer, ipV4Layer, greLayer, innerIpV4Layer);

            return builder.Build(DateTime.Now);
        }

        /// <summary>
        /// This function build an UDP over IPv4 over Ethernet with payload packet.
        /// </summary>
        public static Packet BuildUdpPacket()
        {
            EthernetLayer ethernetLayer =
                new EthernetLayer
                {
                    Source = new MacAddress("68:05:CA:1E:94:1C"),
                    Destination = new MacAddress("90:A2:DA:0D:F7:CD"),
                    EtherType = EthernetType.None, // Will be filled automatically.
                };

            IpV4Layer ipV4Layer =
                new IpV4Layer
                {
                    Source = new IpV4Address("10.128.24.154"),
                    CurrentDestination = new IpV4Address("10.128.24.165"),
                    Fragmentation = IpV4Fragmentation.None,
                    HeaderChecksum = null, // Will be filled automatically.
                    Identification = 123,
                    Options = IpV4Options.None,
                    Protocol = null, // Will be filled automatically.
                    Ttl = 100,
                    TypeOfService = 0,
                };

            UdpLayer udpLayer =
                new UdpLayer
                {
                    SourcePort = 34964,
                    DestinationPort = 49155,
                    Checksum = null, // Will be filled automatically.
                    CalculateChecksumValue = true,
                };

            PayloadLayer payloadLayer =
                new PayloadLayer
                {
                    Data = new Datagram(Encoding.ASCII.GetBytes("hello world")),
                };

            PacketBuilder builder = new PacketBuilder(ethernetLayer, ipV4Layer, udpLayer, payloadLayer);

            return builder.Build(DateTime.Now);
        }


        public static Packet BuildLongUdpPacket()
        {
            EthernetLayer ethernetLayer =
                new EthernetLayer
                {
                    Source = new MacAddress("01:01:01:01:01:01"),
                    Destination = new MacAddress("FF:FF:FF:FF:FF:FF"),
                    EtherType = EthernetType.None, // Will be filled automatically.
                };

            IpV4Layer ipV4Layer =
                new IpV4Layer
                {
                    Source = new IpV4Address("1.1.1.1"),
                    CurrentDestination = new IpV4Address("255.255.255.255"),
                    Fragmentation = IpV4Fragmentation.None,
                    HeaderChecksum = null, // Will be filled automatically.
                    Identification = 123,
                    Options = IpV4Options.None,
                    Protocol = null, // Will be filled automatically.
                    Ttl = 100,
                    TypeOfService = 0,
                };

            UdpLayer udpLayer =
                new UdpLayer
                {
                    SourcePort = 4050,
                    DestinationPort = 25,
                    Checksum = null, // Will be filled automatically.
                    CalculateChecksumValue = true,
                };

            PayloadLayer payloadLayer =
                new PayloadLayer
                {
                    Data = new Datagram(Encoding.ASCII.GetBytes("A very long UDP packet dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")),
                };

            PacketBuilder builder = new PacketBuilder(ethernetLayer, ipV4Layer, udpLayer, payloadLayer);

            return builder.Build(DateTime.Now);
        }

        /// <summary>
        /// This function build an TCP over IPv4 over Ethernet with payload packet.
        /// </summary>
        public static Packet BuildTcpPacket()
        {
            EthernetLayer ethernetLayer =
                new EthernetLayer
                {
                    Source = new MacAddress("01:01:01:01:01:01"),
                    Destination = new MacAddress("02:02:02:02:02:02"),
                    EtherType = EthernetType.None, // Will be filled automatically.
                };

            IpV4Layer ipV4Layer =
                new IpV4Layer
                {
                    Source = new IpV4Address("1.2.3.4"),
                    CurrentDestination = new IpV4Address("11.22.33.44"),
                    Fragmentation = IpV4Fragmentation.None,
                    HeaderChecksum = null, // Will be filled automatically.
                    Identification = 123,
                    Options = IpV4Options.None,
                    Protocol = null, // Will be filled automatically.
                    Ttl = 100,
                    TypeOfService = 0,
                };

            TcpLayer tcpLayer =
                new TcpLayer
                {
                    SourcePort = 4050,
                    DestinationPort = 25,
                    Checksum = null, // Will be filled automatically.
                    SequenceNumber = 100,
                    AcknowledgmentNumber = 50,
                    ControlBits = TcpControlBits.Acknowledgment,
                    Window = 100,
                    UrgentPointer = 0,
                    Options = TcpOptions.None,
                };

            PayloadLayer payloadLayer =
                new PayloadLayer
                {
                    Data = new Datagram(Encoding.ASCII.GetBytes("hello world")),
                };

            PacketBuilder builder = new PacketBuilder(ethernetLayer, ipV4Layer, tcpLayer, payloadLayer);

            return builder.Build(DateTime.Now);
        }

        /// <summary>
        /// This function build a DNS over UDP over IPv4 over Ethernet packet.
        /// </summary>
        public static Packet BuildDnsPacket()
        {
            EthernetLayer ethernetLayer =
                new EthernetLayer
                {
                    Source = new MacAddress("01:01:01:01:01:01"),
                    Destination = new MacAddress("02:02:02:02:02:02"),
                    EtherType = EthernetType.None, // Will be filled automatically.
                };

            IpV4Layer ipV4Layer =
                new IpV4Layer
                {
                    Source = new IpV4Address("1.2.3.4"),
                    CurrentDestination = new IpV4Address("11.22.33.44"),
                    Fragmentation = IpV4Fragmentation.None,
                    HeaderChecksum = null, // Will be filled automatically.
                    Identification = 123,
                    Options = IpV4Options.None,
                    Protocol = null, // Will be filled automatically.
                    Ttl = 100,
                    TypeOfService = 0,
                };

            UdpLayer udpLayer =
                new UdpLayer
                {
                    SourcePort = 4050,
                    DestinationPort = 53,
                    Checksum = null, // Will be filled automatically.
                    CalculateChecksumValue = true,
                };

            DnsLayer dnsLayer =
                new DnsLayer
                {
                    Id = 100,
                    IsResponse = false,
                    OpCode = DnsOpCode.Query,
                    IsAuthoritativeAnswer = false,
                    IsTruncated = false,
                    IsRecursionDesired = true,
                    IsRecursionAvailable = false,
                    FutureUse = false,
                    IsAuthenticData = false,
                    IsCheckingDisabled = false,
                    ResponseCode = DnsResponseCode.NoError,
                    Queries = new[]
                                      {
                                          new DnsQueryResourceRecord(new DnsDomainName("pcapdot.net"),
                                                                     DnsType.A,
                                                                     DnsClass.Internet),
                                      },
                    Answers = null,
                    Authorities = null,
                    Additionals = null,
                    DomainNameCompressionMode = DnsDomainNameCompressionMode.All,
                };

            PacketBuilder builder = new PacketBuilder(ethernetLayer, ipV4Layer, udpLayer, dnsLayer);

            return builder.Build(DateTime.Now);
        }

        /// <summary>
        /// This function build an HTTP over TCP over IPv4 over Ethernet packet.
        /// </summary>
        public static Packet BuildHttpPacket()
        {
            EthernetLayer ethernetLayer =
                new EthernetLayer
                {
                    Source = new MacAddress("01:01:01:01:01:01"),
                    Destination = new MacAddress("02:02:02:02:02:02"),
                    EtherType = EthernetType.None, // Will be filled automatically.
                };

            IpV4Layer ipV4Layer =
                new IpV4Layer
                {
                    Source = new IpV4Address("1.2.3.4"),
                    CurrentDestination = new IpV4Address("11.22.33.44"),
                    Fragmentation = IpV4Fragmentation.None,
                    HeaderChecksum = null, // Will be filled automatically.
                    Identification = 123,
                    Options = IpV4Options.None,
                    Protocol = null, // Will be filled automatically.
                    Ttl = 100,
                    TypeOfService = 0,
                };

            TcpLayer tcpLayer =
                new TcpLayer
                {
                    SourcePort = 4050,
                    DestinationPort = 80,
                    Checksum = null, // Will be filled automatically.
                    SequenceNumber = 100,
                    AcknowledgmentNumber = 50,
                    ControlBits = TcpControlBits.Acknowledgment,
                    Window = 100,
                    UrgentPointer = 0,
                    Options = TcpOptions.None,
                };

            HttpRequestLayer httpLayer =
                new HttpRequestLayer
                {
                    Version = HttpVersion.Version11,
                    Header = new HttpHeader(new HttpContentLengthField(11)),
                    Body = new Datagram(Encoding.ASCII.GetBytes("hello world")),
                    Method = new HttpRequestMethod(HttpRequestKnownMethod.Get),
                    Uri = @"http://pcapdot.net/",
                };

            PacketBuilder builder = new PacketBuilder(ethernetLayer, ipV4Layer, tcpLayer, httpLayer);

            return builder.Build(DateTime.Now);
        }

        /// <summary>
        /// This function build a DNS over UDP over IPv4 over GRE over IPv4 over IPv4 over VLAN Tagged Frame over VLAN Tagged Frame over Ethernet.
        /// </summary>
        public static Packet BuildComplexPacket()
        {
            return PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer
                {
                    Source = new MacAddress("01:01:01:01:01:01"),
                    Destination = new MacAddress("02:02:02:02:02:02"),
                    EtherType = EthernetType.None, // Will be filled automatically.
                },
                new VLanTaggedFrameLayer
                {
                    PriorityCodePoint = ClassOfService.ExcellentEffort,
                    CanonicalFormatIndicator = false,
                    EtherType = EthernetType.None, // Will be filled automatically.
                },
                new VLanTaggedFrameLayer
                {
                    PriorityCodePoint = ClassOfService.BestEffort,
                    CanonicalFormatIndicator = false,
                    EtherType = EthernetType.None, // Will be filled automatically.
                },
                new IpV4Layer
                {
                    Source = new IpV4Address("1.2.3.4"),
                    CurrentDestination = new IpV4Address("11.22.33.44"),
                    Fragmentation = IpV4Fragmentation.None,
                    HeaderChecksum = null, // Will be filled automatically.
                    Identification = 123,
                    Options = IpV4Options.None,
                    Protocol = null, // Will be filled automatically.
                    Ttl = 100,
                    TypeOfService = 0,
                },
                new IpV4Layer
                {
                    Source = new IpV4Address("5.6.7.8"),
                    CurrentDestination = new IpV4Address("55.66.77.88"),
                    Fragmentation = IpV4Fragmentation.None,
                    HeaderChecksum = null, // Will be filled automatically.
                    Identification = 456,
                    Options = new IpV4Options(new IpV4OptionStrictSourceRouting(
                                                      new[]
                                                          {
                                                              new IpV4Address("100.200.100.200"),
                                                              new IpV4Address("150.250.150.250")
                                                          }, 1)),
                    Protocol = null, // Will be filled automatically.
                    Ttl = 200,
                    TypeOfService = 0,
                },
                new GreLayer
                {
                    Version = GreVersion.Gre,
                    ProtocolType = EthernetType.None, // Will be filled automatically.
                    RecursionControl = 0,
                    FutureUseBits = 0,
                    ChecksumPresent = true,
                    Checksum = null, // Will be filled automatically.
                    Key = 100,
                    SequenceNumber = 123,
                    AcknowledgmentSequenceNumber = null,
                    RoutingOffset = null,
                    Routing = new[]
                                      {
                                          new GreSourceRouteEntryIp(
                                              new[]
                                                  {
                                                      new IpV4Address("10.20.30.40"),
                                                      new IpV4Address("40.30.20.10")
                                                  }.AsReadOnly(), 1),
                                          new GreSourceRouteEntryIp(
                                              new[]
                                                  {
                                                      new IpV4Address("11.22.33.44"),
                                                      new IpV4Address("44.33.22.11")
                                                  }.AsReadOnly(), 0)
                                      }.Cast<GreSourceRouteEntry>().ToArray().AsReadOnly(),
                    StrictSourceRoute = false,
                },
                new IpV4Layer
                {
                    Source = new IpV4Address("51.52.53.54"),
                    CurrentDestination = new IpV4Address("61.62.63.64"),
                    Fragmentation = IpV4Fragmentation.None,
                    HeaderChecksum = null, // Will be filled automatically.
                    Identification = 123,
                    Options = new IpV4Options(
                            new IpV4OptionTimestampOnly(0, 1,
                                                        new IpV4TimeOfDay(new TimeSpan(1, 2, 3)),
                                                        new IpV4TimeOfDay(new TimeSpan(15, 55, 59))),
                            new IpV4OptionQuickStart(IpV4OptionQuickStartFunction.RateRequest, 10, 200, 300)),
                    Protocol = null, // Will be filled automatically.
                    Ttl = 100,
                    TypeOfService = 0,
                },
                new UdpLayer
                {
                    SourcePort = 53,
                    DestinationPort = 40101,
                    Checksum = null, // Will be filled automatically.
                    CalculateChecksumValue = true,
                },
                new DnsLayer
                {
                    Id = 10012,
                    IsResponse = true,
                    OpCode = DnsOpCode.Query,
                    IsAuthoritativeAnswer = true,
                    IsTruncated = false,
                    IsRecursionDesired = true,
                    IsRecursionAvailable = true,
                    FutureUse = false,
                    IsAuthenticData = true,
                    IsCheckingDisabled = false,
                    ResponseCode = DnsResponseCode.NoError,
                    Queries =
                            new[]
                                {
                                    new DnsQueryResourceRecord(
                                        new DnsDomainName("pcapdot.net"),
                                        DnsType.Any,
                                        DnsClass.Internet),
                                },
                    Answers =
                            new[]
                                {
                                    new DnsDataResourceRecord(
                                        new DnsDomainName("pcapdot.net"),
                                        DnsType.A,
                                        DnsClass.Internet
                                        , 50000,
                                        new DnsResourceDataIpV4(new IpV4Address("10.20.30.44"))),
                                    new DnsDataResourceRecord(
                                        new DnsDomainName("pcapdot.net"),
                                        DnsType.Txt,
                                        DnsClass.Internet,
                                        50000,
                                        new DnsResourceDataText(new[] {new DataSegment(Encoding.ASCII.GetBytes("Pcap.Net"))}.AsReadOnly()))
                                },
                    Authorities =
                            new[]
                                {
                                    new DnsDataResourceRecord(
                                        new DnsDomainName("pcapdot.net"),
                                        DnsType.MailExchange,
                                        DnsClass.Internet,
                                        100,
                                        new DnsResourceDataMailExchange(100, new DnsDomainName("pcapdot.net")))
                                },
                    Additionals =
                            new[]
                                {
                                    new DnsOptResourceRecord(
                                        new DnsDomainName("pcapdot.net"),
                                        50000,
                                        0,
                                        DnsOptVersion.Version0,
                                        DnsOptFlags.DnsSecOk,
                                        new DnsResourceDataOptions(
                                            new DnsOptions(
                                                new DnsOptionUpdateLease(100),
                                                new DnsOptionLongLivedQuery(1,
                                                                            DnsLongLivedQueryOpCode.Refresh,
                                                                            DnsLongLivedQueryErrorCode.NoError,
                                                                            10, 20))))
                                },
                    DomainNameCompressionMode = DnsDomainNameCompressionMode.All,
                });
        }
    }
}
