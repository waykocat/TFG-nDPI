import java.io.IOException;




public class dpiadapt {
  public native int sendPacket(byte []header , int ipoffset, int ipsize, int hdrize) ;
  public static void main (String args[]) {

	  byte[] header = new byte[5];
	  header[0] = 5;
	  header[1] = 5;
	  header[2] = 5;
	  header[3] = 5;
	  header[4] = 5;
	  int ipoffset = 3;
	  int ipsize = 6;
	  int hdrsize = 30;
	  dpiadapt h = new dpiadapt () ;
	  int r =  h.sendPacket (header, ipoffset, ipsize, hdrsize) ;

	   System.out.println(r);

  }
  static {
	try {
      NativeUtils.loadLibraryFromJar("/libdpiadapt.so");
    } catch (IOException e) {
      e.printStackTrace(); // This is probably not the best way to handle exception :-)
    }
	  //System.loadLibrary ( "dpiadapt" );
  }
}
