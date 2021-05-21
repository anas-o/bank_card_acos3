package bank_Card2;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.List;

import javax.crypto.Cipher;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;


public class INPTCard {
	
	/*
	 * CLEAR CARD
	 * CLA = 0x80; INS = 0x30; P1 = 0x00; P2 = 0x00; no data required
	 */
	private static byte[] APDU_Clear_card	= { (byte)0x80, 0x30, 0x00, 0x00, 0x00 };
	/*
	 * SUBMIT CODE (PIN)
	 * CLA = 0x80; INS = 0x20; P1 = 0x06 for PIN; P2 = 0x00; Lc = 8; data = PIN (12345678)
	 */
	private static byte [] APDU_Submit_PIN 	= { (byte) 0x80, 0x20, 0x06, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
	private static byte [] PIN 				= { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
	/*
	 * SUBMIT CODE (IC)
	 * CLA = 0x80; INS = 0x20; P1 = 0x07 for IC; P2 = 0x00; Lc = 8; data = IC
	 */
	private static byte[] APDU_Submit_IC	= { (byte)0x80, 0x20, 0x07, 0x00, 0x08, 0x41, 0x43, 0x4F, 0x53, 0x54, 0x45, 0x53, 0x54 };
	/*
	 * SELECT FILE
	 * CLA = 0x80; INS = 0xA4; P1 = 0x00; P2 = 0x00; Lc = 2; data = FID
	 * the last 2 bytes (0x0000) will take the FID of the selected file
	 */
	private static byte[] APDU_Select_file	= { (byte)0x80, (byte)0xA4, 0x00, 0x00, 0x02, 0x00, 0x00 };
	
	/*
	 * RSA
	 */
	private static final int KEY_SIZE 		= 1024;
	private static final String Mode 		= "RSA/None/PKCS1Padding";
	// Generate a random RSA key pair, of size = KEY_SIZE
	public static KeyPair generateRSAKeyPair() throws GeneralSecurityException {
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(KEY_SIZE);
		return gen.generateKeyPair();
	}
	// Encryption Function
	public static byte[] encrypt(byte[] plaintext, PublicKey pub) throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance(Mode, "BC");
		cipher.init(Cipher.ENCRYPT_MODE, pub);
		return cipher.doFinal(plaintext);
	}
	// Decryption Function
	public static String decrypt(byte[] ciphertext, PrivateKey pvt) throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance(Mode, "BC");
		cipher.init(Cipher.DECRYPT_MODE, pvt);
		final byte[] plainText = cipher.doFinal(ciphertext);
		String recovered = new String(plainText);
		return recovered;
	}

	public static void main(String[] args) throws CardException, UnsupportedEncodingException, GeneralSecurityException {
		
		// Prepare the provider BC
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		// Generate RSA keys
		KeyPair pair = INPTCard.generateRSAKeyPair();
		
		//*** 1- Connect to the card reader ***
				TerminalFactory tf = TerminalFactory.getDefault();
				CardTerminals lecteurs = tf.terminals();
				List Liste_lecteurs = lecteurs.list();
				CardTerminal lecteur = (CardTerminal)Liste_lecteurs.get(0);
				
				Card card = null;
				System.out.println("Waiting for the card...");
				if (lecteur.isCardPresent()) {
					card = lecteur.connect("*");
					System.out.println("Terminal connected");
					if (card != null) {
						System.out.println("Card Protocol: " + card.getProtocol());
						CardChannel ch = card.getBasicChannel();
						
						//*** 2- Submit Issuer Code (to clear the card) ***
						CommandAPDU Submit_IC	= new CommandAPDU(APDU_Submit_IC);
						ResponseAPDU ra			= ch.transmit(Submit_IC);
						if (ra.getSW() == 0x9000)
							System.out.println(" OK Submit IC; SW = 0x9000");
						else
							System.out.println("Error[2]: " + Integer.toHexString(ra.getSW()));
						
						//*** 3- Clear the card ***
						CommandAPDU Clear_card	= new CommandAPDU(APDU_Clear_card);
						ra						= ch.transmit(Clear_card);
						if (ra.getSW() == 0x9000)
							System.out.println(" OK Clear Card; SW = 0x9000");
						else
							System.out.println("Error[3]: " + Integer.toHexString(ra.getSW()));
						
						//*** 4- Submit Issuer Code (to select the personalization file) ***
						Submit_IC	= new CommandAPDU(APDU_Submit_IC);
						ra			= ch.transmit(Submit_IC);
						if (ra.getSW() == 0x9000)
							System.out.println(" OK Submit IC; SW = 0x9000");
						else
							System.out.println("Error[4]: " + Integer.toHexString(ra.getSW()));
						
						//*** 5- Select Personalization File ***
						APDU_Select_file[5] = (byte)0xFF;
						APDU_Select_file[6] = 0x02;
						CommandAPDU Select_file	= new CommandAPDU(APDU_Select_file);
						ra						= ch.transmit(Select_file);
						if (ra.getSW() == 0x9000)
							System.out.println(" OK Select Personalization File; SW = 0x9000");
						else
							System.out.println("Error[5]: " + Integer.toHexString(ra.getSW()));
						
						//*** 6- Create 3 User Files ***
						/*
						 * WRITE RECORD (on Personalization File)
						 * CLA = 0x80; INS = 0xD2; P1 = 0x00 (Record No. 0); P2 = 0x00; Lc = 4;
						 * data[Option Register]			= 0x00;
						 * data[Security Option Register]	= 0x00;
						 * data[N_OF_FILE = 3]				= 0x03;
						 * data[Personalization Bit = 0]	= 0x00;
						 */
						byte[] APDU_Write_record	= { (byte)0x80, (byte)0xD2, 0x00, 0x00, 0x04, 0x00, 0x00, 0x03, 0x00 };
						CommandAPDU Write_record	= new CommandAPDU(APDU_Write_record);
						ra							= ch.transmit(Write_record);
						if (ra.getSW() == 0x9000)
							System.out.println(" OK, 3 files created; SW = 0x9000");
						else
							System.out.println("Error[6]: " + Integer.toHexString(ra.getSW()));
						
						//*** 7- Warm Reset (to take changes into account) ***
						card.disconnect(true);
						card = lecteur.connect("*");
						System.out.println("Terminal connected");
						ch = card.getBasicChannel();
						
						//*** 8- Submit Issuer Code (to select the management file) ***
						Submit_IC	= new CommandAPDU(APDU_Submit_IC);
						ra			= ch.transmit(Submit_IC);
						if (ra.getSW() == 0x9000)
							System.out.println(" OK Submit IC; SW = 0x9000");
						else
							System.out.println("Error[8]: " + Integer.toHexString(ra.getSW()));
						
						//*** 9- Select Management File ***
						APDU_Select_file[6] = 0x04;
						Select_file	= new CommandAPDU(APDU_Select_file);
						ra			= ch.transmit(Select_file);
						if (ra.getSW() == 0x9000)
							System.out.println(" OK Select Management File; SW = 0x9000");
						else
							System.out.println("Error[9]: " + Integer.toHexString(ra.getSW()));
						
						//*** 10- Configure the user files (by the management file) ***
						/*
						 * WRITE RECORD 0 (on Management File)
						 */
						APDU_Write_record = new byte[11];
						APDU_Write_record[0] = (byte)0x80;	//* CLA = 0x80
						APDU_Write_record[1] = (byte)0xD2;	//* INS = 0xD2
						APDU_Write_record[2] = 0x00;		//* P1 = 0x00 (Record No. 0)
						APDU_Write_record[3] = 0x00;		//* P2 = 0x00
						APDU_Write_record[4] = 0x06;		//* Lc = 6
						APDU_Write_record[5] = (byte)0x80;	//* data[Record length]				= 128 bytes
						APDU_Write_record[6] = 0x04;		//* data[Number of Records]			= 4
						APDU_Write_record[7] = 0x00;		//* data[Read Security Attribute]	= 0x00
						APDU_Write_record[8] = (byte)0x80;	//* data[Write Security Attribute]	= 0x80 (IC)
						APDU_Write_record[9] = (byte)0xAA;	//* data[File identifier - byte 5]	(FID=AA10)
						APDU_Write_record[10] = 0x10;		//* data[File identifier - byte 6]	(FID=AA10)
						Write_record	= new CommandAPDU(APDU_Write_record);
						ra				= ch.transmit(Write_record);
						if (ra.getSW() == 0x9000)
							System.out.println(" OK, file AA10 configured; SW = 0x9000");
						else
							System.out.println("Error[10]: " + Integer.toHexString(ra.getSW()));
						/*
						 * WRITE RECORD 1 (on Management File)
						 */
						APDU_Write_record[2] = 0x01;		//* P1 = 0x01 (Record No. 1)
						APDU_Write_record[5] = 0x40;		//* data[Record length]				= 64 bytes
						APDU_Write_record[6] = 0x01;		//* data[Number of Records]			= 1
						APDU_Write_record[10] = 0x11;		//* data[File identifier - byte 6]	(FID=AA11)
						Write_record	= new CommandAPDU(APDU_Write_record);
						ra				= ch.transmit(Write_record);
						if (ra.getSW() == 0x9000)
							System.out.println(" OK, file AA11 configured; SW = 0x9000");
						else
							System.out.println("Error[10]: " + Integer.toHexString(ra.getSW()));
						/*
						 * WRITE RECORD 2 (on Management File)
						 */
						APDU_Write_record[2] = 0x02;		//* P1 = 0x02 (Record No. 2)
						APDU_Write_record[5] = (byte)0x80;	//* data[Record length]				=  128 bytes
						APDU_Write_record[6] = 0x01;		//* data[Number of Records]			= 1
						APDU_Write_record[7] = 0x40;		//* data[Read Security Attribute]	= 0x40 (PIN)
						APDU_Write_record[8] = (byte)0x80;	//* data[Write Security Attribute]	= 0x80 (IC)
						APDU_Write_record[10] = 0x12;		//* data[File identifier - byte 6]	(FID=AA12)
						Write_record	= new CommandAPDU(APDU_Write_record);
						ra				= ch.transmit(Write_record);
						if (ra.getSW() == 0x9000)
							System.out.println(" OK, file AA12 configured; SW = 0x9000");
						else
							System.out.println("Error[10]: " + Integer.toHexString(ra.getSW()));
						
						//*** 11- Warm Reset (to take changes into account) ***
						card.disconnect(true);
						card = lecteur.connect("*");
						System.out.println("Terminal connected");
						ch = card.getBasicChannel();
						
						//*** 12- Submit Issuer Code (to select the security file) ***
						Submit_IC	= new CommandAPDU(APDU_Submit_IC);
						ra			= ch.transmit(Submit_IC);
						if (ra.getSW() == 0x9000)
							System.out.println(" OK Submit IC; SW = 0x9000");
						else
							System.out.println("Error[12]: " + Integer.toHexString(ra.getSW()));
						
						//*** 13- Select Security File ***
						APDU_Select_file[6] = 0x03;
						Select_file	= new CommandAPDU(APDU_Select_file);
						ra			= ch.transmit(Select_file);
						if (ra.getSW() == 0x9000)
							System.out.println(" OK Select Security File; SW = 0x9000");
						else
							System.out.println("Error[13]: " + Integer.toHexString(ra.getSW()));
						
						//*** 14- Add PIN to the Security file ***
						/*
						 * WRITE RECORD [second record] (PIN)
						 */
						APDU_Write_record = new byte[13];
						APDU_Write_record[0] = (byte)0x80;	//* CLA = 0x80
						APDU_Write_record[1] = (byte)0xD2;	//* INS = 0xD2
						APDU_Write_record[2] = 0x01;		//* P1 = 0x01 (PIN Record)
						APDU_Write_record[3] = 0x00;        //* P2 = 0x00
						APDU_Write_record[4] = 0x08;		//* Lc = 8
						for (int i = 0; i < 8; i++) {
							APDU_Write_record[5+i] = PIN[i];	//* data = PIN
				        }
						Write_record	= new CommandAPDU(APDU_Write_record);
						ra 				= ch.transmit(Write_record);
				         if (ra.getSW() == 0x9000){
				            System.out.println(" OK, Security file configured; SW = 0x9000");            
				        }
				        else
				            System.out.println("Error[14]: "+Integer.toHexString(ra.getSW()));
				         
				       //*** 15- Warm Reset (to take changes into account) ***
							card.disconnect(true);
							card = lecteur.connect("*");
							System.out.println("Terminal connected");
							ch = card.getBasicChannel();
						
						//________________________________TEST___________________________________//
						System.out.println("\n____________________TEST PHASE_______________________");
						
						//*** T1- Select User File 0xAA10 ***
						APDU_Select_file[5] = (byte)0xAA;
						APDU_Select_file[6]	= 0x10;
						Select_file	= new CommandAPDU(APDU_Select_file);
						ra			= ch.transmit(Select_file);
						if (ra.getSW() == 0x9100)
							System.out.println(" OK, file AA10 selected; SW = 0x9100");
						else
							System.out.println("Error[T1]: " + Integer.toHexString(ra.getSW()));
						
						//*** T2- Submit Issuer Code (writing permission) ***
						Submit_IC	= new CommandAPDU(APDU_Submit_IC);
						ra			= ch.transmit(Submit_IC);
						if (ra.getSW() == 0x9000)
							System.out.println(" OK Submit IC; SW = 0x9000");
						else
							System.out.println("Error[T2]: " + Integer.toHexString(ra.getSW()));
						
						//*** T3- Fill in the user file selected ***
						String[] plain_AA10	= new String[4];	//clear data
						byte[][] file_AA10	= new byte[4][];	//cipher data
						plain_AA10[0] = "Mr";
						plain_AA10[1] = "SEGHIR Sami Anas";
						plain_AA10[2] = "0000111122223333";
						plain_AA10[3] = "09052021";
						int i;
						// Encryption with the public key
						System.out.println("\nEncrypted data:");
						for (i = 0; i < 4; i++) {
							file_AA10[i] = INPTCard.encrypt(plain_AA10[i].getBytes(), pair.getPublic());
							System.out.println(byteArrayToHexString(file_AA10[i]));
						}
						for (i = 0; i < 4; i++) {
							byte[] record = file_AA10[i];
							/*
							 * WRITE RECORD (on User File AA10)
							 */
							APDU_Write_record = new byte[133];
							APDU_Write_record[0] = (byte)0x80;	//* CLA = 0x80
							APDU_Write_record[1] = (byte)0xD2;	//* INS = 0xD2
							APDU_Write_record[2] = (byte)i;		//* P1 = Record No. i
							APDU_Write_record[3] = 0x00;		//* P2 = 0x00
							APDU_Write_record[4] = (byte)0x80;	//* Lc = 128
							for (int j = 0; j < record.length; j++)
								APDU_Write_record[5+j] = record[j];	//* data of record i
							Write_record	= new CommandAPDU(APDU_Write_record);
							ra				= ch.transmit(Write_record);
							if (ra.getSW() == 0x9000)
								System.out.println(" OK, record written; SW = 0x9000");
							else
								System.out.println("Error[T3]: " + Integer.toHexString(ra.getSW()));
						}
						
						//*** T4- Select User File 0xAA11 ***
						APDU_Select_file[6]	= 0x11;
						Select_file	= new CommandAPDU(APDU_Select_file);
						ra			= ch.transmit(Select_file);
						if (ra.getSW() == 0x9101)
							System.out.println(" OK, file AA11 selected; SW = 0x9101");
						else
							System.out.println("Error[T4]: " + Integer.toHexString(ra.getSW()));
						
						//*** T5- Submit Issuer Code (writing permission)
						Submit_IC	= new CommandAPDU(APDU_Submit_IC);
						ra			= ch.transmit(Submit_IC);
						if (ra.getSW() == 0x9000)
							System.out.println(" OK Submit IC; SW = 0x9000");
						else
							System.out.println("Error[T5]: " + Integer.toHexString(ra.getSW()));
						
						//*** T6- Fill in the user file selected ***
						//byte[] signature = { 0x7b, 0x73, 0x40, (byte)0x8d, 0x08, 0x1f, 0x7f, 0x06, 0x6c, (byte)0x87, (byte)0xa9, (byte)0xa3, 0x09, (byte)0x9b, 0x03, (byte)0xe4, 0x21, (byte)0xc5, (byte)0x9c, 0x28, (byte)0xce, 0x29, 0x52, 0x13, 0x17, 0x56, 0x7f, 0x4b, (byte)0xc6, 0x75, (byte)0xff, 0x32, (byte)0xf1, (byte)0xb8,  0x7b, 0x2d, (byte)0xa3, 0x65, 0x3b, (byte)0x92, 0x0c, 0x3e, (byte)0xa0, 0x35, 0x59, (byte)0xa9, (byte)0xc9, (byte)0xee, (byte)0xa9, (byte)0x85, 0x09, (byte)0xca, 0x66, 0x04, 0x44, 0x4b, (byte)0xc2, (byte)0xf8, 0x5d, 0x64, 0x76, (byte)0xff, (byte)0xf2, (byte)0xf4 };
						byte[] signature = { 0x76, (byte)0xc7, (byte)0xaa, (byte)0x85, 0x57, 0x79, 0x0a, 0x77, (byte)0x89, 0x17, 0x00, (byte)0xec, 0x4d, 0x19, 0x01, 0x7b, (byte)0xab, (byte)0xee, 0x2d, (byte)0xe8, 0x75, 0x31, 0x3d, 0x39, (byte)0xef, (byte)0xeb, 0x0b, (byte)0xc9, (byte)0xee, (byte)0xbe, (byte)0xa9, (byte)0x83, 0x7d, 0x1f, (byte)0x91, 0x13, (byte)0xf7, 0x44, (byte)0x80, (byte)0x95, (byte)0x90, (byte)0xe0, 0x6a, (byte)0xc4, 0x54, (byte)0xbc, (byte)0xbf, (byte)0xf1, 0x48, 0x0e, 0x7f, (byte)0xa0, (byte)0x85, 0x4b, 0x3f, 0x2b, 0x75, (byte)0xd6, 0x08, (byte)0xd9, 0x7d, 0x59, (byte)0x97, 0x66 };
						/*
						 * WRITE RECORD (on User File AA11)
						 */
						APDU_Write_record = new byte[69];
						APDU_Write_record[0] = (byte)0x80;	//* CLA = 0x80
						APDU_Write_record[1] = (byte)0xD2;	//* INS = 0xD2
						APDU_Write_record[2] = (byte)0x00;	//* P1 = Record No. 0
						APDU_Write_record[3] = 0x00;		//* P2 = 0x00
						APDU_Write_record[4] = 0x40;		//* Lc = 64
						for (i = 0; i < signature.length; i++)
							APDU_Write_record[5+i] = signature[i];	//* data 
						Write_record	= new CommandAPDU(APDU_Write_record);
						ra				= ch.transmit(Write_record);
						if (ra.getSW() == 0x9000)
							System.out.println(" OK, record written; SW = 0x9000");
						else
							System.out.println("Error[T6]: " + Integer.toHexString(ra.getSW()));
						
						//*** T7- Select User File 0xAA12 ***
						APDU_Select_file[6]	= 0x12;
						Select_file	= new CommandAPDU(APDU_Select_file);
						ra			= ch.transmit(Select_file);
						if (ra.getSW() == 0x9102)
							System.out.println(" OK, file AA12 selected; SW = 0x9102");
						else
							System.out.println("Error[T7]: " + Integer.toHexString(ra.getSW()));
						
						//*** T8- Submit Issuer Code (writing permission)
						Submit_IC	= new CommandAPDU(APDU_Submit_IC);
						ra			= ch.transmit(Submit_IC);
						if (ra.getSW() == 0x9000)
							System.out.println(" OK Submit IC; SW = 0x9000");
						else
							System.out.println("Error[T8]: " + Integer.toHexString(ra.getSW()));
						
						//*** T9- Fill in the user file selected ***
						String publicKey_string = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMAf++bK7KuwsytdBeA5VcEoStNAjMPMRcPPthMoz+WH7QLwCXCwVBsEMiG0JyzDrzK7TJ05yNJTHNc7fDBohj8CAwEAAQ==";
						//byte[] publicKey = { 0x30, 0x5C, 0x30, 0x0D, 0x06, 0x09, 0x2A, (byte)0x86, 0x48, (byte)0x86, (byte)0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x4B, 0x00, 0x30, 0x48, 0x02, 0x41, 0x00, (byte)0xD1, (byte)0xE2, (byte)0xD3, 0x7A, (byte)0x88, (byte)0xF7, (byte)0xCA, 0x3B, (byte)0xE7, 0x66, (byte)0x8A, (byte)0xF2, 0x15, 0x13, 0x3D, 0x42, (byte)0x82, (byte)0xD4, 0x2A, 0x4C, 0x19, 0x6D, (byte)0x94, 0x65, (byte)0x95, (byte)0xB3, (byte)0xCA, (byte)0xBB, 0x2F, (byte)0x99, (byte)0x81, 0x70, 0x47, (byte)0xF4, 0x6D, (byte)0xBD, 0x62, (byte)0xE1, (byte)0xB4, (byte)0xFC, 0x1D, (byte)0xEF, (byte)0xBC, 0x50, 0x66, 0x29, (byte)0xCF, 0x47, 0x67, (byte)0xA0, (byte)0xB4, 0x5A, (byte)0x97, (byte)0xA3, (byte)0xE0, (byte)0xDF, 0x3C, 0x3E, 0x73, 0x7F, (byte)0x8B, 0x1C, 0x2D, 0x27, 0x02, 0x03, 0x01, 0x00, 0x01 };
						/*
						 * WRITE RECORD (on User File AA12)
						 */
						APDU_Write_record = new byte[133];
						APDU_Write_record[0] = (byte)0x80;	//* CLA = 0x80
						APDU_Write_record[1] = (byte)0xD2;	//* INS = 0xD2
						APDU_Write_record[2] = (byte)0x00;	//* P1 = Record No. 0
						APDU_Write_record[3] = 0x00;		//* P2 = 0x00
						APDU_Write_record[4] = (byte)0x80;	//* Lc = 128
						byte[] publicKey = publicKey_string.getBytes();
						for (i = 0; i < publicKey.length; i++)
							APDU_Write_record[5+i] = publicKey[i];	//* data 
						Write_record	= new CommandAPDU(APDU_Write_record);
						ra				= ch.transmit(Write_record);
						if (ra.getSW() == 0x9000)
							System.out.println(" OK, record written; SW = 0x9000");
						else
							System.out.println("Error[T9]: " + Integer.toHexString(ra.getSW()));
						
						//*** T10- Select User File 0xAA10 ***
						APDU_Select_file[6]	= 0x10;
						Select_file	= new CommandAPDU(APDU_Select_file);
						ra			= ch.transmit(Select_file);
						if (ra.getSW() == 0x9100)
							System.out.println(" OK, file AA10 selected; SW = 0x9100");
						else
							System.out.println("Error[T10]: " + Integer.toHexString(ra.getSW()));
						
						//*** T11- Read records from file AA10 ***
						System.out.println("\n Decrypted data:");
						for (i = 0; i < 4; i++) {
							/*
							 * READ RECORD
							 * CLA = 0x80; INS = 0xB2; P1 = Record No. i; P2 = 0x00; Le = 128 (length to read)
							 */
							byte[] APDU_Read_record = { (byte)0x80, (byte)0xB2, (byte)i, 0x00, (byte)0x80 };
							CommandAPDU Read_record	= new CommandAPDU(APDU_Read_record);
							ra						= ch.transmit(Read_record);
							if (ra.getSW() == 0x9000) {
								System.out.print(" OK, reading file AA10; record " + i + ": ");
								// Decrypted data
								System.out.println(INPTCard.decrypt(ra.getData(), pair.getPrivate()));
								//System.out.println(new String(ra.getData()));
							}
							else
								System.out.println("Error[T11]: " + Integer.toHexString(ra.getSW()));
						}
						
						//*** T12- Select User File 0xAA11 ***
						APDU_Select_file[6]	= 0x11;
						Select_file	= new CommandAPDU(APDU_Select_file);
						ra			= ch.transmit(Select_file);
						if (ra.getSW() == 0x9101)
							System.out.println(" OK, file AA11 selected; SW = 0x9101");
						else
							System.out.println("Error[T12]: " + Integer.toHexString(ra.getSW()));
						
						//*** T13- Read records from file AA11 ***
						/*
						 * READ RECORD
						 * CLA = 0x80; INS = 0xB2; P1 = Record No. 0; P2 = 0x00; Le = 64 (length to read)
						 */
						byte[] APDU_Read_record = { (byte)0x80, (byte)0xB2, 0x00, 0x00, 0x40 };
						CommandAPDU Read_record	= new CommandAPDU(APDU_Read_record);
						ra						= ch.transmit(Read_record);
						if (ra.getSW() == 0x9000) {
							System.out.print(" OK, reading file AA11; Signature:\n");
							System.out.println(new String(ra.getData()));
						}
						else
							System.out.println("Error[T13]: " + Integer.toHexString(ra.getSW()));
						
						//*** T14- Select User File 0xAA12 ***
						APDU_Select_file[6]	= 0x12;
						Select_file	= new CommandAPDU(APDU_Select_file);
						ra			= ch.transmit(Select_file);
						if (ra.getSW() == 0x9102)
							System.out.println(" OK, file AA12 selected; SW = 0x9102");
						else
							System.out.println("Error[T14]: " + Integer.toHexString(ra.getSW()));
						
						
						//*** T15- Submit PIN (reading permission) ***
						CommandAPDU Submit_PIN	= new CommandAPDU(APDU_Submit_PIN);
						ra						= ch.transmit(Submit_PIN);
						if (ra.getSW() == 0x9000)
							System.out.println(" OK Submit PIN; SW = 0x9000");
						else
							System.out.println("Error[T15]: " + Integer.toHexString(ra.getSW()));
						
						//*** T16- Read records from file AA12 ***
						/*
						 * READ RECORD
						 * CLA = 0x80; INS = 0xB2; P1 = Record No. 0; P2 = 0x00; Le = 128 (length to read)
						 */
						APDU_Read_record[4]	= (byte)0x80;
						Read_record	= new CommandAPDU(APDU_Read_record);
						ra			= ch.transmit(Read_record);
						if (ra.getSW() == 0x9000) {
							System.out.print(" OK, reading file AA12; Public key: ");
							System.out.println(new String(ra.getData()));
						}
						else
							System.out.println("Error[T16]: " + Integer.toHexString(ra.getSW()));

						card.disconnect(true);
					}
				}
	}
	
	public static String byteArrayToHexString(byte[] b) {
		String result = "";
		for (int i=0; i<b.length; i++) {
			result += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
		}
		return result;
	}

}

