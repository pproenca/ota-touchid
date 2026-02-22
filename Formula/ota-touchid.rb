class OtaTouchid < Formula
  desc "Over-the-air Touch ID authentication for remote Macs"
  homepage "https://github.com/pproenca/ota-touchid"
  url "https://github.com/pproenca/ota-touchid/releases/download/v0.1.1/ota-touchid-macos-arm64.tar.gz"
  version "0.1.1"
  sha256 "7742e37f2eed897fc3901747999507822ca7030f11930e302fcbe3e209902394"
  license "MIT"

  depends_on :macos
  depends_on arch: :arm64

  def install
    bin.install "ota-touchid"
  end

  def caveats
    <<~EOS
      To set up the server (Mac with Touch ID):
        ota-touchid setup

      To pair a client (remote Mac):
        ota-touchid pair <psk>

      To authenticate:
        ota-touchid auth --reason sudo
    EOS
  end

  test do
    assert_match "OTA Touch ID", shell_output("#{bin}/ota-touchid help")
  end
end
