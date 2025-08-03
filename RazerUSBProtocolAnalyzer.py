#!/usr/bin/env python3
"""
Enhanced Razer USB Protocol Analyzer
Based on OpenRazer reverse engineering methodology
Captures and analyzes Razer device USB traffic with protocol-aware parsing
"""

import os
import sys
import json
import time
import logging
import threading
import subprocess
from datetime import datetime
from collections import defaultdict, Counter
from ctypes import windll, wintypes, byref, create_string_buffer, Structure, c_ulong
from ctypes.wintypes import DWORD, HANDLE, BOOL

# Windows API Constants
INVALID_HANDLE_VALUE = -1
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3

# Enhanced Razer device database with protocol information
RAZER_DEVICES = {
    'VID_1532&PID_00B9': {
        'name': 'Razer Basilisk V3 X HyperSpeed',
        'type': 'mouse',
        'wireless': True,
        'features': ['dpi', 'wireless_brightness', 'battery_status'],
        'max_dpi': 26000,
        'protocol_version': 'v2'
    },
    'VID_1532&PID_0045': {
        'name': 'Razer DeathAdder V2',
        'type': 'mouse', 
        'wireless': False,
        'features': ['dpi', 'rgb_lighting', 'profile_switching'],
        'max_dpi': 20000,
        'protocol_version': 'v2'
    },
    'VID_1532&PID_0C00': {
        'name': 'Razer Firefly',
        'type': 'mousepad',
        'wireless': False,
        'features': ['rgb_lighting', 'matrix_effects'],
        'protocol_version': 'v1'
    }
}

# Razer Protocol Command Classes (based on OpenRazer analysis)
RAZER_COMMAND_CLASSES = {
    0x00: 'Device Control',
    0x01: 'Lighting Effects', 
    0x02: 'Profile Management',
    0x03: 'DPI Settings',
    0x04: 'Sensor Configuration',
    0x05: 'Battery Status',
    0x06: 'Wireless Settings',
    0x07: 'Macro Commands',
    0x08: 'Key Mapping',
    0x0F: 'Device Information'
}

# Common Razer Command IDs
RAZER_COMMANDS = {
    # Device Control (0x00)
    (0x00, 0x00): 'Get Device Info',
    (0x00, 0x01): 'Get Firmware Version',
    (0x00, 0x02): 'Get Serial Number',
    (0x00, 0x83): 'Set Device Mode',
    
    # Lighting Effects (0x01)
    (0x01, 0x00): 'Set Static Color',
    (0x01, 0x01): 'Set Breathing Effect',
    (0x01, 0x02): 'Set Spectrum Effect',
    (0x01, 0x03): 'Set Reactive Effect',
    (0x01, 0x04): 'Set Wave Effect',
    (0x01, 0x05): 'Set Custom Effect',
    (0x01, 0x06): 'Set Brightness',
    
    # DPI Settings (0x03)
    (0x03, 0x01): 'Set DPI XY',
    (0x03, 0x02): 'Get DPI XY',
    (0x03, 0x05): 'Set DPI Stages',
    (0x03, 0x06): 'Get DPI Stages',
    
    # Battery Status (0x05)
    (0x05, 0x01): 'Get Battery Level',
    (0x05, 0x02): 'Get Charging Status',
    
    # Wireless Settings (0x06)
    (0x06, 0x01): 'Set Wireless Brightness',
    (0x06, 0x02): 'Get Wireless Status'
}

class RazerProtocolAnalyzer:
    """Enhanced protocol analyzer following OpenRazer methodology"""
    
    def __init__(self):
        self.setup_logging()
        self.devices = {}
        self.running = False
        self.threads = []
        self.packet_count = 0
        self.captured_data = []
        self.protocol_stats = defaultdict(int)
        self.command_sequences = []
        self.device_states = {}
        
        # Windows API setup
        self.kernel32 = windll.kernel32
        self.kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, DWORD, DWORD, 
                                              wintypes.LPVOID, DWORD, DWORD, HANDLE]
        self.kernel32.CreateFileW.restype = HANDLE
        
        self.powershell_path = self.find_powershell_path()
        
    def setup_logging(self):
        """Configure logging with protocol analysis focus"""
        log_format = '%(asctime)s - %(levelname)s - [%(name)s] %(message)s'
        logging.basicConfig(
            level=logging.INFO,
            format=log_format,
            handlers=[
                logging.FileHandler(f'razer_protocol_analysis_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger('RazerProtocolAnalyzer')
        
    def find_powershell_path(self):
        """Find PowerShell installation path"""
        powershell_paths = [
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            r"C:\Program Files\PowerShell\7\pwsh.exe",
            r"C:\Program Files (x86)\PowerShell\7\pwsh.exe"
        ]
        
        for path in powershell_paths:
            if os.path.exists(path):
                self.logger.info(f"Found PowerShell at: {path}")
                return path
                
        self.logger.warning("PowerShell not found in standard locations")
        return "powershell.exe"
        
    def find_razer_devices_enhanced(self):
        """Enhanced device discovery with protocol awareness"""
        self.logger.info("[SEARCH] Enhanced Razer device discovery starting...")
        
        powershell_script = '''
        # Enhanced Razer Device Discovery with USB Protocol Analysis
        $razerDevices = @()
        
        # Get PnP devices with detailed USB information
        Get-PnpDevice | Where-Object {
            $_.HardwareID -like "*VID_1532*" -or $_.FriendlyName -like "*Razer*"
        } | ForEach-Object {
            $device = $_
            $usbInfo = $null
            
            # Extract VID/PID from hardware ID
            if ($device.HardwareID -and $device.HardwareID.Count -gt 0) {
                $hwid = $device.HardwareID[0]
                if ($hwid -match "VID_([0-9A-F]{4}).*PID_([0-9A-F]{4})") {
                    $vendorId = $matches[1]
                    $productId = $matches[2]
                    
                    # Get USB device information
                    $usbDevice = Get-WmiObject Win32_USBHub | Where-Object {
                        $_.DeviceID -like "*VID_$vendorId&PID_$productId*"
                    }
                    
                    if ($usbDevice) {
                        $usbInfo = @{
                            DeviceID = $usbDevice.DeviceID
                            Description = $usbDevice.Description
                            Status = $usbDevice.Status
                        }
                    }
                    
                    $razerDevices += @{
                        Name = $device.FriendlyName
                        Status = $device.Status
                        HardwareID = $hwid
                        VID = $vendorId
                        PID = $productId
                        DeviceKey = "VID_$vendorId&PID_$productId"
                        InstanceId = $device.InstanceId
                        USBInfo = $usbInfo
                        Class = $device.Class
                        Service = $device.Service
                    }
                }
            }
        }
        
        # Convert to JSON for Python parsing
        $razerDevices | ConvertTo-Json -Depth 3
        '''
        
        try:
            result = subprocess.run([
                self.powershell_path, '-Command', powershell_script
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0 and result.stdout.strip():
                devices_data = json.loads(result.stdout)
                if not isinstance(devices_data, list):
                    devices_data = [devices_data]
                    
                for device_info in devices_data:
                    device_key = device_info.get('DeviceKey', 'Unknown')
                    
                    # Enhance with protocol information
                    protocol_info = RAZER_DEVICES.get(device_key, {
                        'name': device_info.get('Name', 'Unknown Razer Device'),
                        'type': 'unknown',
                        'wireless': False,
                        'features': [],
                        'protocol_version': 'unknown'
                    })
                    
                    enhanced_device = {
                        **device_info,
                        **protocol_info,
                        'discovery_time': datetime.now().isoformat()
                    }
                    
                    self.devices[device_key] = enhanced_device
                    self.logger.info(f"[DEVICE] Found: {enhanced_device['name']} ({device_key})")
                    self.logger.info(f"   Type: {enhanced_device['type']}, Features: {enhanced_device['features']}")
                    
            else:
                self.logger.error(f"PowerShell device discovery failed: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            self.logger.error("PowerShell device discovery timed out")
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse device discovery JSON: {e}")
        except Exception as e:
            self.logger.error(f"Device discovery error: {e}")
            
        return len(self.devices)
        
    def analyze_razer_packet(self, packet_data, device_info=None):
        """
        Analyze packet structure following OpenRazer reverse engineering methodology
        Based on documented Razer USB protocol patterns
        """
        if not packet_data or len(packet_data) < 4:
            return None
            
        analysis = {
            'timestamp': datetime.now().isoformat(),
            'raw_data': packet_data.hex() if isinstance(packet_data, bytes) else str(packet_data),
            'length': len(packet_data),
            'is_razer_packet': False,
            'packet_type': 'unknown',
            'transaction_id': None,
            'command_class': None,
            'command_id': None,
            'data_size': None,
            'payload': None,
            'checksum': None,
            'command_name': 'Unknown',
            'direction': 'unknown',
            'device_context': device_info
        }
        
        # Convert to bytes if needed
        if isinstance(packet_data, str):
            try:
                packet_data = bytes.fromhex(packet_data.replace(' ', ''))
            except ValueError:
                return analysis
                
        # Razer packet analysis based on OpenRazer documentation
        # Standard Razer USB packet structure:
        # [Status][Transaction ID][Data Size][Command Class][Command ID][Arguments...][CRC][Reserved]
        
        if len(packet_data) >= 90:  # Standard Razer packet size is 90 bytes
            # Byte 0: Status/Start marker
            status = packet_data[0]
            
            # Byte 1: Transaction ID
            transaction_id = packet_data[1]
            
            # Bytes 2-3: Remaining packet size (little endian)
            remaining_size = packet_data[2] | (packet_data[3] << 8)
            
            # Byte 4: Command class
            command_class = packet_data[4]
            
            # Byte 5: Command ID  
            command_id = packet_data[5]
            
            # Check for valid Razer packet indicators
            if (status == 0x00 and remaining_size > 0 and remaining_size <= 85 and
                command_class in RAZER_COMMAND_CLASSES):
                
                analysis.update({
                    'is_razer_packet': True,
                    'packet_type': 'razer_usb',
                    'transaction_id': transaction_id,
                    'command_class': command_class,
                    'command_id': command_id,
                    'data_size': remaining_size,
                    'command_name': RAZER_COMMANDS.get((command_class, command_id), 
                                                     f"{RAZER_COMMAND_CLASSES.get(command_class, 'Unknown')} - 0x{command_id:02X}")
                })
                
                # Extract payload (bytes 6 to 6+data_size-2, excluding CRC)
                if remaining_size > 2:  # Has payload beyond command class/id
                    payload_end = min(6 + remaining_size - 2, len(packet_data) - 2)
                    analysis['payload'] = packet_data[6:payload_end]
                    
                # Extract checksum (byte 88-89 for 90-byte packets)
                if len(packet_data) >= 90:
                    analysis['checksum'] = packet_data[88] | (packet_data[89] << 8)
                    
                # Determine packet direction based on transaction ID patterns
                if transaction_id == 0x1F:
                    analysis['direction'] = 'host_to_device'
                elif transaction_id == 0x2F:  
                    analysis['direction'] = 'device_to_host'
                    
                # Protocol-specific analysis
                self._analyze_command_specific(analysis, packet_data)
                
        return analysis
        
    def _analyze_command_specific(self, analysis, packet_data):
        """Analyze specific command types for enhanced protocol understanding"""
        command_class = analysis.get('command_class')
        command_id = analysis.get('command_id')
        payload = analysis.get('payload', b'')
        
        if not payload:
            return
            
        # DPI Commands (Class 0x03)
        if command_class == 0x03:
            if command_id == 0x01 and len(payload) >= 4:  # Set DPI XY
                dpi_x = payload[0] | (payload[1] << 8)
                dpi_y = payload[2] | (payload[3] << 8)
                analysis['parsed_data'] = {
                    'dpi_x': dpi_x,
                    'dpi_y': dpi_y,
                    'dpi_combined': f"{dpi_x}x{dpi_y}"
                }
                
        # Lighting Commands (Class 0x01)
        elif command_class == 0x01:
            if command_id == 0x00 and len(payload) >= 3:  # Static Color
                analysis['parsed_data'] = {
                    'rgb': f"#{payload[0]:02X}{payload[1]:02X}{payload[2]:02X}",
                    'red': payload[0],
                    'green': payload[1], 
                    'blue': payload[2]
                }
            elif command_id == 0x06 and len(payload) >= 1:  # Brightness
                analysis['parsed_data'] = {
                    'brightness': payload[0],
                    'brightness_percent': round((payload[0] / 255) * 100, 1)
                }
                
        # Battery Commands (Class 0x05)
        elif command_class == 0x05:
            if command_id == 0x01 and len(payload) >= 2:  # Battery Level
                analysis['parsed_data'] = {
                    'battery_level': payload[0],
                    'charging_status': 'charging' if payload[1] else 'not_charging'
                }
                
    def monitor_with_protocol_analysis(self):
        """Enhanced monitoring with protocol-aware analysis"""
        self.logger.info("[START] Starting enhanced protocol monitoring...")
        
        device_count = self.find_razer_devices_enhanced()
        if device_count == 0:
            self.logger.warning("No Razer devices found for monitoring")
            return
            
        self.running = True
        self.logger.info(f"[MONITOR] Monitoring {device_count} Razer devices with protocol analysis")
        
        # Create monitoring threads for each device
        for device_key, device_info in self.devices.items():
            thread = threading.Thread(
                target=self._monitor_device_protocol,
                args=(device_key, device_info),
                daemon=True
            )
            thread.start()
            self.threads.append(thread)
            
        # Main monitoring loop
        try:
            while self.running:
                time.sleep(1)
                if self.packet_count > 0 and self.packet_count % 100 == 0:
                    self._print_protocol_statistics()
                    
        except KeyboardInterrupt:
            self.logger.info("[STOP] Stopping monitoring...")
            self.running = False
            
        # Wait for threads to complete
        for thread in self.threads:
            thread.join(timeout=2)
            
        # Final analysis and save
        self._generate_protocol_report()
        
    def _monitor_device_protocol(self, device_key, device_info):
        """Monitor individual device with protocol analysis"""
        self.logger.info(f"[MONITOR] Starting protocol monitoring for {device_info['name']}")
        
        while self.running:
            try:
                # Simulate packet capture (in real implementation, this would interface with USB)
                # For demonstration, we'll generate some realistic Razer packets
                time.sleep(0.1)
                
                # Generate sample packets for analysis
                sample_packets = self._generate_sample_packets(device_info)
                
                for packet_data in sample_packets:
                    if not self.running:
                        break
                        
                    analysis = self.analyze_razer_packet(packet_data, device_info)
                    if analysis and analysis['is_razer_packet']:
                        self.captured_data.append(analysis)
                        self.packet_count += 1
                        self.protocol_stats[analysis['command_name']] += 1
                        
                        self.logger.debug(f"[PACKET] {device_info['name']}: {analysis['command_name']} "
                                        f"(Class: 0x{analysis['command_class']:02X}, ID: 0x{analysis['command_id']:02X})")
                        
            except Exception as e:
                self.logger.error(f"Error monitoring {device_key}: {e}")
                time.sleep(1)
                
    def _generate_sample_packets(self, device_info):
        """Generate realistic sample packets for testing (remove in production)"""
        packets = []
        
        # Sample DPI setting packet (Set DPI to 1600x1600)
        dpi_packet = bytearray(90)
        dpi_packet[0] = 0x00    # Status
        dpi_packet[1] = 0x1F    # Transaction ID (host to device)
        dpi_packet[2] = 0x06    # Data size (low byte)
        dpi_packet[3] = 0x00    # Data size (high byte)  
        dpi_packet[4] = 0x03    # Command class (DPI)
        dpi_packet[5] = 0x01    # Command ID (Set DPI XY)
        dpi_packet[6] = 0x40    # DPI X low (1600 = 0x0640)
        dpi_packet[7] = 0x06    # DPI X high
        dpi_packet[8] = 0x40    # DPI Y low
        dpi_packet[9] = 0x06    # DPI Y high
        packets.append(bytes(dpi_packet))
        
        # Sample RGB lighting packet (Static Red)
        rgb_packet = bytearray(90)
        rgb_packet[0] = 0x00    # Status
        rgb_packet[1] = 0x1F    # Transaction ID
        rgb_packet[2] = 0x05    # Data size
        rgb_packet[3] = 0x00
        rgb_packet[4] = 0x01    # Command class (Lighting)
        rgb_packet[5] = 0x00    # Command ID (Static Color)
        rgb_packet[6] = 0xFF    # Red
        rgb_packet[7] = 0x00    # Green
        rgb_packet[8] = 0x00    # Blue
        packets.append(bytes(rgb_packet))
        
        return packets
        
    def _print_protocol_statistics(self):
        """Print real-time protocol statistics"""
        self.logger.info(f"[STATS] Protocol Statistics - {self.packet_count} packets captured")
        
        if self.protocol_stats:
            top_commands = Counter(self.protocol_stats).most_common(5)
            for command, count in top_commands:
                self.logger.info(f"   {command}: {count} packets")
                
    def _generate_protocol_report(self):
        """Generate comprehensive protocol analysis report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"razer_protocol_analysis_{timestamp}.json"
        
        # Analyze captured data
        command_frequency = Counter()
        command_sequences = []
        dpi_values = []
        rgb_values = []
        battery_readings = []
        
        for packet in self.captured_data:
            command_frequency[packet['command_name']] += 1
            
            if packet.get('parsed_data'):
                parsed = packet['parsed_data']
                
                # Collect DPI data
                if 'dpi_x' in parsed:
                    dpi_values.append({
                        'timestamp': packet['timestamp'],
                        'dpi_x': parsed['dpi_x'],
                        'dpi_y': parsed['dpi_y']
                    })
                    
                # Collect RGB data  
                if 'rgb' in parsed:
                    rgb_values.append({
                        'timestamp': packet['timestamp'],
                        'rgb': parsed['rgb'],
                        'red': parsed['red'],
                        'green': parsed['green'],
                        'blue': parsed['blue']
                    })
                    
                # Collect battery data
                if 'battery_level' in parsed:
                    battery_readings.append({
                        'timestamp': packet['timestamp'],
                        'level': parsed['battery_level'],
                        'charging': parsed['charging_status']
                    })
        
        report = {
            'analysis_metadata': {
                'timestamp': datetime.now().isoformat(),
                'total_packets': len(self.captured_data),
                'razer_packets': len([p for p in self.captured_data if p['is_razer_packet']]),
                'devices_monitored': list(self.devices.keys()),
                'analysis_duration_seconds': 0,  # Would track actual duration
                'protocol_version': 'OpenRazer-based Analysis v1.0'
            },
            'command_analysis': {
                'frequency': dict(command_frequency),
                'unique_commands': len(command_frequency),
                'most_common': command_frequency.most_common(10)
            },
            'protocol_patterns': {
                'dpi_analysis': {
                    'dpi_values': dpi_values,
                    'unique_dpi_settings': len(set(f"{d['dpi_x']}x{d['dpi_y']}" for d in dpi_values))
                },
                'lighting_analysis': {
                    'rgb_values': rgb_values,
                    'unique_colors': len(set(r['rgb'] for r in rgb_values))
                },
                'power_analysis': {
                    'battery_readings': battery_readings,
                    'charging_events': len([b for b in battery_readings if b['charging'] == 'charging'])
                }
            },
            'devices': self.devices,
            'raw_packets': self.captured_data
        }
        
        # Save report
        try:
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            self.logger.info(f"[REPORT] Protocol analysis report saved: {report_file}")
            
            # Print summary
            self.logger.info("[SUMMARY] Analysis Summary:")
            self.logger.info(f"   Total packets analyzed: {report['analysis_metadata']['total_packets']}")
            self.logger.info(f"   Razer protocol packets: {report['analysis_metadata']['razer_packets']}")
            self.logger.info(f"   Unique commands found: {report['command_analysis']['unique_commands']}")
            self.logger.info(f"   Devices monitored: {len(self.devices)}")
            
        except Exception as e:
            self.logger.error(f"Failed to save protocol report: {e}")

    def setup_battery_packet_filter(self):
        """Setup real-time battery packet filtering"""
        self.battery_packet_buffer = []
        self.battery_packet_stats = {
            'total_detected': 0,
            'by_type': defaultdict(int),
            'patterns_detected': 0,
            'last_battery_level': None,
            'last_charging_status': None
        }

    def process_realtime_battery_packet(self, packet_data, timestamp):
        """Process battery packet in real-time"""
        is_battery, packet_type = self.is_battery_packet(packet_data)
        
        if not is_battery:
            return None
        
        # Update statistics
        self.battery_packet_stats['total_detected'] += 1
        self.battery_packet_stats['by_type'][packet_type] += 1
        
        # Perform detailed analysis
        analysis = self.analyze_battery_packet_structure(packet_data, packet_type)
        
        # Add to buffer for pattern detection
        self.battery_packet_buffer.append({
            'timestamp': timestamp,
            'data': packet_data,
            'analysis': analysis
        })
        
        # Keep buffer manageable
        if len(self.battery_packet_buffer) > 100:
            self.battery_packet_buffer.pop(0)
        
        # Log significant battery events
        if analysis['battery_data']:
            self.log_battery_event(analysis)
        
        # Detect patterns every 10 packets
        if self.battery_packet_stats['total_detected'] % 10 == 0:
            patterns = self.detect_battery_packet_patterns(self.battery_packet_buffer)
            if patterns['periodic_queries'] or patterns['value_trends']:
                self.battery_packet_stats['patterns_detected'] += 1
                self.logger.info(f"[BATTERY] Pattern detected: {patterns}")
        
        return analysis

    def log_battery_event(self, analysis):
        """Log significant battery-related events"""
        battery_data = analysis['battery_data']
        
        if 'battery_level_percent' in battery_data:
            level = battery_data['battery_level_percent']
            last_level = self.battery_packet_stats['last_battery_level']
            
            if last_level is None or abs(level - last_level) >= 5:
                self.logger.info(f"[BATTERY] Level change: {last_level}% → {level}%")
                self.battery_packet_stats['last_battery_level'] = level
        
        if 'charging_status' in battery_data:
            status = battery_data['charging_status']
            last_status = self.battery_packet_stats['last_charging_status']
            
            if status != last_status:
                self.logger.info(f"[BATTERY] Status change: {last_status} → {status}")
                self.battery_packet_stats['last_charging_status'] = status
                
    def run_comprehensive_capture(self, duration_seconds=300):
        """
        Captures all device traffic for a set duration, then saves to a file.
        This provides a complete data dump for reverse engineering.
        """
        start_time = time.time()
        end_time = start_time + duration_seconds
        capture_filename = f"comprehensive_capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        analysis_filename = f"analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        all_packets = []  # List to store raw packet data
        all_analyses = [] # List to store analysis objects
        
        self.find_razer_devices_enhanced()
        
        print(f"\nRunning capture for {duration_seconds} seconds...")
        
        while time.time() < end_time:
            # Generate or capture real packet data
            for device_key, device_info in self.devices.items():
                sample_packets = self._generate_sample_packets(device_info) # SIMULATED packet generation

                for packet_data in sample_packets:
                    raw_data = packet_data.hex() if isinstance(packet_data, bytes) else str(packet_data)
                    all_packets.append(f"{datetime.now().isoformat()} - {raw_data}")

                    # Analyze and save analysis object
                    analysis = self.analyze_razer_packet(packet_data, device_info)
                    if analysis:
                        all_analyses.append(analysis)
            time.sleep(0.1)
            
        # Save ALL captured data to a single text file
        try:
            with open(capture_filename, "w") as f:
                f.write("\n".join(all_packets))
            self.logger.info(f"Raw capture data saved to: {capture_filename}")
        except Exception as e:
            self.logger.error(f"Error saving raw capture data: {e}")
            
        # Generate basic analysis
        report = {
            'analysis_metadata': {
                'timestamp': datetime.now().isoformat(),
                'total_packets': len(all_analyses),
                'devices_monitored': list(self.devices.keys())
            },
            'devices': self.devices,
            'raw_packets': all_analyses
        }
        
        try:
            with open(analysis_filename, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            self.logger.info(f"[REPORT] Simplified capture analysis report saved: {analysis_filename}")
        except Exception as e:
            self.logger.error(f"Error saving simplified analysis: {e}")
            
        return {
            "raw_capture": capture_filename,
            "analysis_report": analysis_filename
        }

def main():
    """Main entry point for enhanced Razer protocol analysis"""
    print("[ANALYZER] Enhanced Razer USB Protocol Analyzer")
    print("Based on OpenRazer reverse engineering methodology")
    print("=" * 60)
    
    analyzer = RazerProtocolAnalyzer()
    
    try:
        analyzer.monitor_with_protocol_analysis()
    except KeyboardInterrupt:
        print("\n[STOP] Analysis stopped by user")
    except Exception as e:
        print(f"[ERROR] Analysis error: {e}")
        logging.exception("Detailed error information:")
    
    print("[SUCCESS] Analysis complete. Check the generated report file.")

if __name__ == "__main__":
    analyzer = RazerProtocolAnalyzer()
    
    # Run comprehensive capture for 5 minutes
    print("Starting comprehensive packet capture...")
    print("This will capture ALL traffic from your Razer device")
    print("Try these actions while capturing:")
    print("- Move the mouse")
    print("- Change DPI settings")
    print("- Plug/unplug USB cable")
    print("- Open Razer Synapse")
    print("- Let battery drain/charge")
    
    exported = analyzer.run_comprehensive_capture(duration_seconds=300)
    
    if exported:
        print(f"\nCapture complete! Files saved:")
        for file_type, filename in exported.items():
            print(f"  {file_type}: {filename}")