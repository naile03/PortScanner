import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.logging.*;

public class PortScanner {

    // Logger setup
    private static final Logger logger = Logger.getLogger(PortScanner.class.getName());

    static {
        try {
            FileHandler fileHandler = new FileHandler("port_scan.log", true);
            fileHandler.setFormatter(new SimpleFormatter());
            logger.addHandler(fileHandler);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Method to scan port
    public static void scanPort(String ip, int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(ip, port), 1000);
            System.out.println("[+] " + ip + ":" + port + " is open");
            logger.info("Open port is found: " + ip + ":" + port);
        } catch (Exception e) {
            // Port is closed or unreachable, no action needed
        }
    }

    // Method to scan target (IP)
    public static void scanTarget(String ip, List<Integer> ports) {
        System.out.println("Scanning " + ip + "...");
        ExecutorService executorService = Executors.newFixedThreadPool(10); // Pool with 10 threads
        for (int port : ports) {
            executorService.submit(() -> scanPort(ip, port));
        }
        executorService.shutdown();
    }

    // Method to resolve domain to IP
    public static String resolveDomain(String target) {
        try {
            InetAddress inetAddress = InetAddress.getByName(target);
            return inetAddress.getHostAddress();
        } catch (UnknownHostException e) {
            return target; // Return as is if not resolvable
        }
    }

    // Method to parse port range input (e.g., "20-80" or "22,80,443")
    public static List<Integer> parsePorts(String portsArg) {
        List<Integer> ports = new ArrayList<>();
        if (portsArg.contains("-")) {
            String[] range = portsArg.split("-");
            int start = Integer.parseInt(range[0]);
            int end = Integer.parseInt(range[1]);
            for (int i = start; i <= end; i++) {
                ports.add(i);
            }
        } else {
            String[] portList = portsArg.split(",");
            for (String port : portList) {
                ports.add(Integer.parseInt(port));
            }
        }
        return ports;
    }

    // Main method
    public static void main(String[] args) {
        if (args.length != 2) {
            System.out.println("Usage: java PortScanner <target> <ports>");
            return;
        }

        String target = args[0];
        String portsArg = args[1];

        // Resolve domain to IP if needed
        String targetIp = resolveDomain(target);

        // Parse port range
        List<Integer> ports = parsePorts(portsArg);

        // Scan the target
        if (target.contains("/")) { // If it's a subnet (e.g., 192.168.1.0/24)
            try {
                String[] parts = target.split("/");
                String network = parts[0];
                int numHosts = Integer.parseInt(parts[1]);

                // Iterate over the network and scan each IP
                InetAddress networkAddress = InetAddress.getByName(network);
                for (int i = 1; i <= numHosts; i++) {
                    String ip = networkAddress.getHostAddress().substring(0, networkAddress.getHostAddress().lastIndexOf(".") + 1) + i;
                    scanTarget(ip, ports);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            // If individual IP
            scanTarget(targetIp, ports);
        }
    }
}
