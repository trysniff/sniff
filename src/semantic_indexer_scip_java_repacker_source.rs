pub(crate) const LAUNCHER_REPACKER: &str = r#"
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Enumeration;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

public final class LauncherRepacker {
  private LauncherRepacker() {}

  public static void main(String[] args) throws Exception {
    if (args.length != 4) {
      throw new IllegalArgumentException(
          "expected launcher, replacement, output, and target entry arguments");
    }
    Path launcher = Path.of(args[0]);
    Path replacement = Path.of(args[1]);
    Path output = Path.of(args[2]);
    String target = args[3];
    byte[] replacementBytes = Files.readAllBytes(replacement);
    CRC32 replacementCrc = new CRC32();
    replacementCrc.update(replacementBytes);
    int replacements = 0;
    try (ZipFile input = new ZipFile(launcher.toFile());
        ZipOutputStream rebuilt = new ZipOutputStream(Files.newOutputStream(output))) {
      Enumeration<? extends ZipEntry> entries = input.entries();
      while (entries.hasMoreElements()) {
        ZipEntry source = entries.nextElement();
        boolean replacing = source.getName().equals(target);
        ZipEntry destination = replacing ? replacementEntry(source) : new ZipEntry(source);
        if (replacing && source.getMethod() == ZipEntry.STORED) {
          destination.setSize(replacementBytes.length);
          destination.setCompressedSize(replacementBytes.length);
          destination.setCrc(replacementCrc.getValue());
        }
        rebuilt.putNextEntry(destination);
        if (replacing) {
          rebuilt.write(replacementBytes);
          replacements++;
        } else if (!source.isDirectory()) {
          try (InputStream contents = input.getInputStream(source)) {
            contents.transferTo(rebuilt);
          }
        }
        rebuilt.closeEntry();
      }
    }
    if (replacements != 1) {
      Files.deleteIfExists(output);
      throw new IllegalStateException(
          "expected exactly one " + target + " entry, found " + replacements);
    }
  }

  private static ZipEntry replacementEntry(ZipEntry source) {
    ZipEntry destination = new ZipEntry(source.getName());
    destination.setMethod(source.getMethod());
    if (source.getComment() != null) destination.setComment(source.getComment());
    if (source.getExtra() != null) destination.setExtra(source.getExtra());
    if (source.getLastModifiedTime() != null) {
      destination.setLastModifiedTime(source.getLastModifiedTime());
    }
    if (source.getLastAccessTime() != null) {
      destination.setLastAccessTime(source.getLastAccessTime());
    }
    if (source.getCreationTime() != null) {
      destination.setCreationTime(source.getCreationTime());
    }
    return destination;
  }
}
"#;
