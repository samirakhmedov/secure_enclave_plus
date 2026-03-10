#
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html.
# Run `pod lib lint secure_enclave_plus.podspec` to validate before publishing.
#
Pod::Spec.new do |s|
  s.name             = 'secure_enclave_plus'
  s.version          = '1.0.0'
  s.summary          = 'Apple Secure Enclave implementation for Flutter.'
  s.description      = <<-DESC
Flutter plugin for Apple's Secure Enclave — hardware-backed key generation,
encryption, decryption, signing, and verification using EC P-256 keys.
                       DESC
  s.homepage         = 'https://github.com/samirakhmedov/secure_enclave_plus'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'Samir Akhmedov' => 'lutrak.developer@gmail.com' }
  s.source           = { :path => '.' }
  s.source_files = 'Classes/**/*'
  s.dependency 'Flutter'
  s.platform = :ios, '12.0'

  # Flutter.framework does not contain a i386 slice.
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES', 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386' }
  s.swift_version = '5.0'
end
