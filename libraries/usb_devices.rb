# InSpec Resource: usb_devices
# File: usb_devices.rb

require 'libusb'

class USBDevices < Inspec.resource(1)
  name 'usb_devices'
  desc 'Verify properties of USB devices connected to the system.'

  example "
    describe usb_devices do
      it { should exist }
      its('device_ids') { should include '046d:c52b' }
      its('device_ids') { should_not include 'ffff:ffff' }
      its('descriptions') { should include 'Unifying Receiver' }
      its('device_count') { should be > 0 }
    end
  "

  def initialize
    @devices = load_devices
  end

  def exist?
    !@devices.empty?
  end

  def device_ids
    @devices.map { |d| d[:id] }
  end

  def descriptions
    @devices.map { |d| d[:description] }
  end
  
  def manufacturers
    @devices.map {|d| d[:manufacturer] }
  end
  
  def products
    @devices.map {|d| d[:product] }
  end

  def device_count
    @devices.count
  end
  
  private

  def load_devices
    usb = LIBUSB::Context.new
    devices = []
    begin
      usb.devices.each do |device|
        # Use filter tables from devdocs
          devices << {
              bus: device.bus_number.to_s.rjust(3, '0'),
              device: device.device_address.to_s.rjust(3, '0'),
              id: "#{device.idVendor.to_s(16).rjust(4,'0')}:#{device.idProduct.to_s(16).rjust(4, '0')}", # Format as hex string
              description: device_description(device),
              manufacturer: device.manufacturer,
              product: device.product
          }
      end
    rescue LIBUSB::Error => e
      # use error resource to log error from inspec
      puts "Error accessing USB devices: #{e.message}"
      return []
    ensure
      usb.close if usb
    end
    return devices
  end
  
  def device_description(device)
    begin
      device.product || "Unknown Device" # Fallback if product name unavailable
    rescue
      "Error getting device description" # Handle potential description errors 
    end
  end

end
