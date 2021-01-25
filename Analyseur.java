import java.io.*;
import java.util.*;
import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;

public class Analyseur {
	
	File f;
	Scanner scan;
	Scanner scanNbOctets;
	boolean TCP;
	boolean ipv4;
	TestJtree Ttree;
	DefaultMutableTreeNode racine;
	int offset=1;
	
	public Analyseur(File f) throws FileNotFoundException {
		this.f=f;
		scan = new Scanner(this.f);
		scanNbOctets = new Scanner(this.f);
		TCP=false;
		ipv4=false;
	}
	
    /*---------------Methode regroupant et synchronisant toute les methodes ----------------*/

	public void analyse(File f) throws IOException {
		int cpt=0;
		BufferedWriter writer = new BufferedWriter(new FileWriter(f));
		scanNbOctets.next();
		String s=scan.next();
		
		try {
			while(checkOffsetFormat(s)) {
				cpt++;
				String tName="Trame :"+cpt;
				racine = new DefaultMutableTreeNode("Trame: "+cpt+ ", "+ cptOctets()+" octets capturés");
				String res="\n\n\n"+tName+"\n";
				res+=this.Ethernet();
				if(ipv4) {
					res+="\n";
					res+=this.IP();
					res+="\n";
					if(TCP) {
						res+=this.TCP();
						res+="\n";
						res+=this.HTTP();
					}
					else {
						res+="\n Protocole non TCP, impossible d'analyser la suite";
					}
				}
				else {
					res+="\n Protocole ipv6, impossible d'analyser la suite";
				}
				
				JTree tree = new JTree(racine);
				Ttree= new TestJtree(tree,cpt,tName);
				Ttree.setVisible(true);
				System.out.println(res);
				writer.write(res);
				offset=1;
	
				scan.nextLine();
				s=scan.next();
			}
			
		} catch (NoSuchElementException e) {
			System.out.println("Fin de fichier");
			writer.close();
		}
		
		
	}
    /*-------------------------------Methodes d'annalyse -----------------------------------------*/

	public String Ethernet() {
		//scan.next(); //Skip du premier numero de ligne
		
		int cpt=0;
        DefaultMutableTreeNode eth = new DefaultMutableTreeNode(":--------Ethernet--------:");
		
		String mac1="";
		String mac1h="";
		
		for (int i = 0; i < 6; i++) {
			String s = scan.next();
			checkOffset();
			if(i<5){
				mac1+=Integer.parseInt(s,16)+":";
				mac1h+=s+":";		
			}
			else {
				mac1+=Integer.parseInt(s,16);
				mac1h+=s;	
			}
		}
		mac1="Add Mac Dest: "+mac1h+" ("+mac1+")"+"\n";
		eth.insert(new DefaultMutableTreeNode(mac1), cpt++);
		
		String mac2="";
		String mac2h="";
		for (int i = 0; i < 6; i++) {
			String s = scan.next();
			checkOffset();
			if(i<5){
				mac2+=Integer.parseInt(s,16)+":";
				mac2h+=s+":";
			}
			else {
				mac2+=Integer.parseInt(s,16);
				mac2h+=s;
			}
		}
		mac2="Add Mac Dest: "+mac2h+" ("+mac2+")"+"\n";
		eth.insert(new DefaultMutableTreeNode(mac2), cpt++);
		
		String typ="";
		
		typ+=scan.next();
		checkOffset();
		typ+=scan.next();
		checkOffset();
		
		if(typ.equals("0800")) {
			ipv4=true;
			typ="Type: IPv4 (0x"+typ+")\n";
		}
		else {
			typ="Type: IPv6 (0x"+typ+")\n";

		}
		eth.insert(new DefaultMutableTreeNode(typ), cpt++);

		racine.add(eth);
		return ":-----------En-tete Ethernet-----------: \n"+mac1+mac2+typ;
	}
	
	public String HTTP() {
		int cpt=0;
        DefaultMutableTreeNode http = new DefaultMutableTreeNode(":-----------HTTP----------:");

		String res="";
		String s="";
		String meth="";
						
		while(!(s=scan.next()).equals("20")) {
			meth+=s;
			checkOffset();
		}
		checkOffset();

		meth=HexToString(meth)+" ";
	
		String url="";
		while(!(s=scan.next()).equals("20")) {
			url+=s;
			checkOffset();
		}
		checkOffset();

		url=HexToString(url)+" ";
		
		String vrs="";
		while(!(s=scan.next()).equals("0d")) {
			vrs+=s;
			checkOffset();
		}
		checkOffset();

		vrs=HexToString(vrs)+" ";
		http.insert(new DefaultMutableTreeNode(meth+url+vrs), cpt++);

		res+=meth+url+vrs+"\n";
		
		String rEnd="";
		scan.next();
		checkOffset();

		for (int i = 0; i < 2; i++) {
			rEnd+=scan.next();
			checkOffset();

		}
		try {
			
			while (!(rEnd.equals("0d0a"))) {
				res+="\n";
				
				String enTete=rEnd;
				while(!(s=scan.next()).equals("20")) {
					enTete+=s;

					checkOffset();

				}
				checkOffset();

				enTete=this.HexToString(enTete)+" ";
				
				String val="";
				while(!(s=scan.next()).equals("0d")) {
					val+=s;
					checkOffset();
				}
				checkOffset();

				val=HexToString(val)+" ";

				rEnd="";
				scan.next();
				checkOffset();

				for (int i = 0; i < 2; i++) {
					rEnd+=scan.next();
					checkOffset();

				}
				http.insert(new DefaultMutableTreeNode(enTete+val), cpt++);

				res+=enTete+val;
				racine.add(http);

			}
			
			return "\n:---------------En-tete HTTP--------------: \n"+res;
			
		} catch (NoSuchElementException e) {
			e.printStackTrace();
			return res;
		}
	}
	public String IP() {
        DefaultMutableTreeNode ip = new DefaultMutableTreeNode(":--------IP---------:");
        int cpt=0;
		int v;
		String s=":----------------En-tête IP------------------:\n";
		String type="";
		String intermediaire;
		int tailleoption;
		boolean optionconnu=false;
		int pointeur=0;
		type+=scan.next();
		checkOffset();
		char c=getCharFromString(type,0);

		if(c=='4'){
			s= s+"Type: 4\n";

		}

		ip.insert(new DefaultMutableTreeNode("Type: "+c), cpt++);

		char i= getCharFromString(type,1);
		type=Character.toString(i);
		int size=Integer.parseInt(type,16);
		tailleoption=(size-5)*4;
		size=size*4;
		
		ip.insert(new DefaultMutableTreeNode("Nombre d'octet dans l'entete IP: "+Integer.toString(size)), cpt++);

		s=s+ "Nombre d'octet dans l'entete IP: "+Integer.toString(size)+" octet \n";
		type="";
		
		type+=scan.next();
		checkOffset();
		
		ip.insert(new DefaultMutableTreeNode("TOS: "+ type), cpt++);
		s= s +"TOS: "+ type+"\n";
		
		type="";
		for(v=0;v<2;v++) {
			type+=scan.next();
			checkOffset();
		}
		size=Integer.parseInt(type,16);
		
		ip.insert(new DefaultMutableTreeNode("Longueur: "+ Integer.toString(size)), cpt++);
		s= s+ "Longueur: "+ Integer.toString(size)+"\n";
		
		type="";
		for(v=0;v<2;v++) {
			type+=scan.next();
			checkOffset();
		}
		size=Integer.parseInt(type,16);
		ip.insert(new DefaultMutableTreeNode("Identifiant:0X"+type+"(" +size+" )"), cpt++);
		s=s + "Identifiant="+type+ "("+size+")\n";
		type=""+scan.next();
		checkOffset();
		 c=getCharFromString(type,0);
		 intermediaire=Character.toString(c);
		 size=Integer.parseInt(intermediaire,16);
		 boolean df=false;
		 boolean mf=false;
		 
	     DefaultMutableTreeNode flags = new DefaultMutableTreeNode("Flags");
	     int cpt2=0;
		 if(size==0) {
			 mf=false;
			 df=false;
			 s=s + "MF: 0 et DF: 0 (0X"+ type+")\n";
			 flags.insert(new DefaultMutableTreeNode("MF: 0 et DF: 0 (0X"+type+")"), cpt2++);

		 }
		 if(size==2) {
			 mf=true;
			df= false;
			
			s=s+ "MF :1 et DF:0;(0X"+ type+")\n";
			flags.insert(new DefaultMutableTreeNode("MF :1 et DF: 0 (0X"+type+")"), cpt2++);

		 }
		 if(size==4) {
			 mf=false;
			 df=true;
			 
			 s=s+ "MF: 0 et DF: 1 (0X"+ type+")\n";
			 flags.insert(new DefaultMutableTreeNode("MF: 0 et DF: 1 (0X"+type+")"), cpt2++);

		 }
		 if(size>5) {
			 mf=true;
			 df=true;
			 
			 s=s+ "MF: 1 et DF: 1("+ type+")\n";
			 flags.insert(new DefaultMutableTreeNode("MF: 1 et DF: 1 '"+type+")"), cpt2++);

		 }
		ip.add(flags);
		type+=scan.next();
		checkOffset();
		size=Integer.parseInt(type,16);

		if((mf==false)&& (df==true)) {
			size=size-16384;
		}
		if((mf==true) && (df==false)) {
			size=size-8192;
		}
		 if((mf== true )&& (df==true)) {
			 size=size-24576;
		 }
		 

		s=s+ "Fragment d'offset: "+Integer.toString(size)+"\n";
		ip.insert(new DefaultMutableTreeNode("Fragment d'offset: "+Integer.toString(size)), cpt++);

		type="";
		type+= scan.next();
		checkOffset();
		size=Integer.parseInt(type,16);
		s= s+ "TTL: " +size+"\n";
		ip.insert(new DefaultMutableTreeNode("TTL: " +size), cpt++);
		type="";
		type+=scan.next();
		checkOffset();
		size=Integer.parseInt(type,16);
		if(size==1) {
			type="ICMP\n";
		}
		if(size==2){
			type="IGMP\n";
		}
		if(size==6){
			type="TCP\n";
			TCP=true;
		}
		if (size==17) {
			type="UDP\n";
		}
		s=s + "protocole: "+ type;
		ip.insert(new DefaultMutableTreeNode("protocole: "+ type), cpt++);

		type="";
		
		for(v=0;v<2;v++){
			type+=scan.next();
			checkOffset();
		}

		
		s=s+ "Checksum: "+ type+"\n";
		ip.insert(new DefaultMutableTreeNode("Checksum: "+ type), cpt++);

		type="";
		for(v=0;v<4;v++) {
			size=0;
			intermediaire="";
			intermediaire+=scan.next();
			checkOffset();
			
			size=Integer.parseInt(intermediaire,16);
			type=type+"."+Integer.toString(size);
		}
		
		
		s= s+ "IP src: "+ type+"\n";
		ip.insert(new DefaultMutableTreeNode("IP src: "+ type), cpt++);

		type="";
		for(v=0;v<4;v++) {
			size=0;
			intermediaire="";
			intermediaire+=scan.next();
			checkOffset();
			size=Integer.parseInt(intermediaire,16);
			type=type+Integer.toString(size)+".";
		}
	
		s=s+ "IP dst: "+type+"\n";
		ip.insert(new DefaultMutableTreeNode("IP dst: "+ type), cpt++);

	    DefaultMutableTreeNode opt = new DefaultMutableTreeNode("Options");
	    int cpt3=0;
		while(tailleoption!=0) {
			type=scan.next();
			checkOffset();
			optionconnu=false;
			tailleoption--;
			if (type.equals("00")) {
				opt.insert(new DefaultMutableTreeNode("Pas d'options"), cpt3++);

				break;
				
			}
			if (type.equals("01")) {
				s=s+ "0ption No operation \n";
				opt.insert(new DefaultMutableTreeNode("Option No operation"), cpt3++);
				optionconnu=true;
				
			}
			
			if (type.equals("07")) {
				s=s+"Record Route (RR)\n";
				opt.insert(new DefaultMutableTreeNode("Record Route (RR)"), cpt3++);
				
				type=scan.next();
				checkOffset();
				tailleoption--;
				size=Integer.parseInt(type,16);
				s=s+ "Taille: "+size;
				opt.insert(new DefaultMutableTreeNode("Taille: "+size), cpt3++);

				type=scan.next();
				checkOffset();
				tailleoption--;
				pointeur=Integer.parseInt(type,16);
				s=s+ "Pointeur :"+pointeur;
				opt.insert(new DefaultMutableTreeNode("Pointeur :"+pointeur), cpt3++);

				for(v=0;v<size-3;v++) {
					type=scan.next();
					checkOffset();
					tailleoption--;
					s=s+ "données "+type;
					
			}
				s=s+"\n";
				optionconnu=true;
			}
			
			if (type.equals("44")) {
				s=s+"Time Stamp (TS)\n";
				opt.insert(new DefaultMutableTreeNode("\"Time Stamp (TS)"), cpt3++);

				type=scan.next();
				checkOffset();
				tailleoption--;
				size=Integer.parseInt(type,16);
				s=s+ "Taille: "+size;
				opt.insert(new DefaultMutableTreeNode("Taille: "+size), cpt3++);

				type=scan.next();
				checkOffset();
				tailleoption--;
				pointeur=Integer.parseInt(type,16);
				s=s+ "Pointeur: "+pointeur;
				opt.insert(new DefaultMutableTreeNode("Pointeur: "+pointeur), cpt3++);

				for(v=0;v<size-3;v++) {
					type=scan.next();
					checkOffset();
					tailleoption--;
					
					
			}
				optionconnu=true;
				
				
				
				//type;
			}
			
			if(type.equals("83")) {
				s=s+ "Option Loose Routing \n";
				opt.insert(new DefaultMutableTreeNode("Option Loose Routing"), cpt3++);

				type=scan.next();
				checkOffset();
				tailleoption--;
				size=Integer.parseInt(type,16);
				s=s+ "Taille: "+size;
				opt.insert(new DefaultMutableTreeNode("Taille: "+size), cpt3++);

				for(v=0;v<size-2;v++) {
					type=scan.next();
					checkOffset();
					tailleoption--;
				    
					
			}
				optionconnu=true;
				s= s+ "Reste de l'option non pris en charge";
				opt.insert(new DefaultMutableTreeNode("Reste de l'option non pris en charge"), cpt3++);

				//demande pour le calcul d'adresse IP.
			}
			
			if(type.equals("89")) {
				s=s+"Strict Routing ";
				opt.insert(new DefaultMutableTreeNode("Strict Routing "), cpt3++);

				type=scan.next();
				checkOffset();
				tailleoption--;
				size=Integer.parseInt(type,16);
				s=s+ "taille "+size;
				type=scan.next();
				checkOffset();
				tailleoption--;
				pointeur=Integer.parseInt(type,16);
				s=s+ "pointeur "+pointeur+ " route Data :";
				opt.insert(new DefaultMutableTreeNode("Pointeur :"+pointeur+ " route Data :"), cpt3++);

				
				i=0;
				while(size!=0) {
					
					type="";
					for(v=0;v<4;v++) {
						type+=scan.next();
						checkOffset();
						size--;
						tailleoption--;
					}
					i++;
					s=s+" -route "+i+" ="+type+"\n";
					optionconnu=true;
				}
				
			}
		}
		ip.add(opt);
		
				int compteurpadding=0;
				while(tailleoption!=0){
					scan.next();
					checkOffset();
					compteurpadding++;
					
				}
				s=s+"Nombre octet de padding="+ compteurpadding+"\n";
				ip.insert(new DefaultMutableTreeNode("Nombre octet de padding: "+ compteurpadding), cpt++);

			
		
		racine.add(ip);
		return s;
		
	}
	
	public String TCP() {
	    DefaultMutableTreeNode tcp = new DefaultMutableTreeNode(":--------TCP--------:");
	    int cpt=0;
		String s=":--------------- En-tête TCP ------------------:\n";
		int v;
		boolean optionconnu=false;
		String ports= "";
		String intermediaire;
		int res=0;
		int compteurpadding=0;
		int sizeoption=0;
		
		for(v=0;v<2 ;v++) {
			ports+=scan.next();
			checkOffset();
			
		}
		res=Integer.parseInt(ports,16);
		s= s+ "Port source: "+ Integer.toString(res)+"\n";
		tcp.insert(new DefaultMutableTreeNode("Port source: "+ Integer.toString(res)), cpt++);

		ports="";
		for(v=0;v<2;v++) {
			ports+=scan.next();
			checkOffset();
			
		}
		
		res=Integer.parseInt(ports,16);

		s= s+ "Port destination: "+ Integer.toString(res)+"\n";
		tcp.insert(new DefaultMutableTreeNode("Port destination: "+ Integer.toString(res)), cpt++);

		ports="";
		for(v=0;v<4;v++) {
			ports+=scan.next();
			checkOffset();
		}
		Long resl;
		resl=Long.parseLong(ports,16);
		s= s+ "Numero de sequence: "+ Long.toString(resl)+"\n";
		tcp.insert(new DefaultMutableTreeNode("Numero de sequence: "+ Long.toString(resl)), cpt++);

		ports="";

		
		for(v=0;v<4;v++) {
			ports+=scan.next();
			checkOffset();
					
		}
		Long resol;
		resol=Long.parseLong(ports,16);
		s= s+ "Numero Ack: "+ Long.toString(resol)+"\n";
		tcp.insert(new DefaultMutableTreeNode("Numero Ack: "+ Long.toString(resol)), cpt++);


		ports=""+scan.next();
		checkOffset();
		char c=getCharFromString(ports,0);
		intermediaire=Character.toString(c);
		res=Integer.parseInt(intermediaire,16);
		s=s+"Offset= "+Integer.toString(res)+"\n";
		tcp.insert(new DefaultMutableTreeNode("Offset= "+Integer.toString(res)), cpt++);

		sizeoption= (res-5)*4 ;
		
		
		
		ports=""+scan.next();
		checkOffset();
		c=getCharFromString(ports,0);
		intermediaire=Character.toString(c);
		res=Integer.parseInt(intermediaire,16);
		
		int urg=0,ack=0;
		if(res==1) {
			urg=0;
			ack=1;
		}
		if(res==2) {
			urg=1;
		}
		if(res==3) {
			urg=1;
			ack=1;
		}
		s=s+"URG: "+urg+ " et ACK: "+ack;
		tcp.insert(new DefaultMutableTreeNode("URG: "+urg+ " et ACK: "+ack), cpt++);
		
		c=getCharFromString(ports,1);
		intermediaire=Character.toString(c);
		res=Integer.parseInt(intermediaire,16);
	
		int psh=0,rst=0,syn=0,fin=0;
		if(res==0){
			psh=0;
			rst=0;
			syn=0;
			fin=0;
		}
		if (res==1) {
			psh=0;
			rst=0;
			syn=0;
			fin=0;
		}
		
		if (res==1) {
			psh=0;
			rst=0;
			syn=0;
			fin=1;
		}
		
		if (res==2) {
			psh=0;
			rst=0;
			syn=1;
			fin=0;
		}
		
		if (res==3) {
			psh=0;
			rst=0;
			syn=1;
			fin=1;
		}
		
		if (res==4) {	
			psh=0;
			rst=1;
			syn=0;
			fin=0;
		}
		if (res==5) {
			psh=0;
			rst=1;
			syn=0;
			fin=1;
		}
		if (res==6) {
			psh=0;
			rst=1;
			syn=1;
			fin=0;
		}
		if (res==7) {
			psh=0;
			rst=1;
			syn=1;
			fin=1;
		}
		if (res==8) {
			psh=1;
			rst=0;
			syn=0;
			fin=0;
		}
		if (res==9) {
			psh=1;
			rst=0;
			syn=0;
			fin=1;
		}
		if (res==10) {
			psh=1;
			rst=0;
			syn=1;
			fin=0;
		}
		if (res==11) {
			psh=1;
			rst=0;
			syn=1;
			fin=1;
		}
		if (res==12) {
			psh=1;
			rst=1;
			syn=0;
			fin=0;
		}
		if (res==13) {
			psh=1;
			rst=1;
			syn=0;
			fin=1;
		}
		if (res==14) {
			psh=1;
			rst=1;
			syn=1;
			fin=0;
		}
		if(res==15) {
			psh=1;
			rst=1;
			syn=1;
			fin=1;
		}
		s=s+"PSH: "+psh+ "RST "+rst+ "SYN: "+syn+"FIN: "+fin;
		tcp.insert(new DefaultMutableTreeNode("PSH: "+psh+ "RST "+rst+ "SYN: "+syn+"FIN: "+fin), cpt++);

		ports="";
		for(v=0;v<2;v++) {
			ports+=scan.next();
			checkOffset();
			
		}
		res=Integer.parseInt(ports,16);
		s=s+"\nFenetre= "+Integer.toString(res)+"\n";
		tcp.insert(new DefaultMutableTreeNode("Fenetre: "+Integer.toString(res)), cpt++);
		
		ports="";
		for(v=0;v<2;v++) {
			ports+=scan.next();
			checkOffset();
			
		}
		s=s+"Checksum: "+ports+"\n";
		tcp.insert(new DefaultMutableTreeNode("Checksum: "+ports), cpt++);

		
		ports="";
		for(v=0;v<2;v++) {
			ports+=scan.next();
			checkOffset();
		

		}
		res=Integer.parseInt(ports,16);
		s=s+"Pointeur d'urgence: "+Integer.toString(res)+"\n";
		tcp.insert(new DefaultMutableTreeNode("Pointeur d'urgence: "+Integer.toString(res)), cpt++);
		int compteur=0;

		
		ports="";
		
		DefaultMutableTreeNode option = new DefaultMutableTreeNode(":--------Option--------:");
		while(sizeoption!=0) {
			
				ports="";	
				optionconnu=false;
				ports=scan.next();
		
				checkOffset();
				sizeoption--;
			
		if(ports.equals("00")) {
			
			break;
		}
	
			compteurpadding++;
			if(ports.equals("01")) {
				s=s+ "option NOP \n";
				option.insert(new DefaultMutableTreeNode("Option: NOP"), compteur++);
				optionconnu=true;
				}
			
			if(ports.equals("02")) {
				ports=scan.next();
				checkOffset();
				sizeoption--;
				compteurpadding++;
				ports="";
				for(v=0;v<2;v++){
					ports+=scan.next();
					checkOffset();
					sizeoption--;
				
		}
				s=s+"Option MSS\n";
				option.insert(new DefaultMutableTreeNode("Option: MSS"), compteur++);
				optionconnu=true;
			}
			
			if(ports.equals("03")) {
				
				ports=scan.next();
				checkOffset();
				sizeoption--;
				ports=scan.next();
				checkOffset();
				sizeoption--;
				res=Integer.parseInt(ports,16);
				s=s+"Option WSPOT decalage ="+res+"\n";
				option.insert(new DefaultMutableTreeNode("Option: WSPOT decalage"), compteur++);
				optionconnu=true;
				
				
			}
			
			if (ports.equals("04")) {
			s=s+"Option Sack permitted \n";
			option.insert(new DefaultMutableTreeNode("Option: Sack permitted"), compteur++);
			optionconnu=true;
			}
			
			if(ports.equals("05")) {
				s= s+ "option SACK ";
				ports=scan.next();
				checkOffset();
				sizeoption--;
				res=Integer.parseInt(ports,16);
				s=s+ "taille "+res;
				for(v=0;v<res-2;v++) {
					ports=scan.next();
					checkOffset();
					sizeoption--;
					s=s+ "données "+ports;
					
					
				}
				s=s+"\n";
				optionconnu=true;
				
			}
				
			
			
			if(ports.equals("06")) {
				s=s+"Option Echo\n";
				option.insert(new DefaultMutableTreeNode("Option: Echo"), compteur++);
				for(v=0;v<6;v++) {
					ports+=scan.next();
					checkOffset();
					sizeoption--;
				}
				optionconnu=true;
			}
			
			if(ports.equals("07")) {
				s=s+"Option Echo reply\n";
				option.insert(new DefaultMutableTreeNode("Option: Echo reply"), compteur++);
				for(v=0;v<5;v++) {
					ports+=scan.next();
					checkOffset();
					sizeoption--;
			
				}
				optionconnu=true;
			}
			if (ports.equals("08")){
				Long timestampvalue;
				Long timechoreply;
				optionconnu=true;
				ports=scan.next();
				checkOffset();
				sizeoption--;
				ports="";
				for(v=0;v<4;v++) {
					ports+=scan.next();
					checkOffset();
					sizeoption--;
			
					
				}
				timestampvalue=Long.parseLong(ports,16);
				ports="";
				for(v=0;v<4;v++) {
					ports+=scan.next();
					checkOffset();
					sizeoption--;
		
				
			}
				 timechoreply=Long.parseLong(ports,16);
				 s=s+"TSOPT - Time Stamp Option avec timestampvalue= "+ timestampvalue+ " timechoreply ="+timechoreply+"\n";
				 option.insert(new DefaultMutableTreeNode("Option: Time Stamp timestampvalue = "+Long.toString(timestampvalue)+ " timechoreply = "+Long.toString(timechoreply)), compteur++);
				
			}
			if(ports.equals("09")) {
				scan.next();
				checkOffset();
				sizeoption--;
				optionconnu=true;
				s=s+"Option Partial Order Connection Permitted\n";
				option.insert(new DefaultMutableTreeNode("Option: Partial Order Connection permitted"), compteur++);
				
			}
			if(ports.equals("0a")) {
				s=s+"Option Partial Order Service Profile\n";
				option.insert(new DefaultMutableTreeNode("Option: Partial Order Service ProfileO"), compteur++);
				scan.next();
				checkOffset();
				sizeoption--;
		
				scan.next();
				sizeoption--;
				optionconnu=true;
			}
			if(ports.equals("0b")) {
				s=s+"Otpion CC\n";
				option.insert(new DefaultMutableTreeNode("Option: CC"), compteur++);
				optionconnu=true;
			}
			
			if(ports.equals("Oc")) {
				s=s+"Otpion CC.NEW\n";
				option.insert(new DefaultMutableTreeNode("Option: CC.NEW"), compteur++);
				optionconnu=true;
			}
			
			if(ports.equals("0d")) {
				s=s+"CC.ECHO\n";
				option.insert(new DefaultMutableTreeNode("Option: CC.ECHO"), compteur++);
				optionconnu=true;
			}
			
			if (ports.equals("Oe")){
				s=s+ "Option TCP Alternate Checksum Request\n";
				option.insert(new DefaultMutableTreeNode("Option: TCP Alternate Checksum Request"), compteur++);
				optionconnu=true;
			}
			

			if (ports.equals("0f")) {
				s=s+"TCP Alternate Checksum Data\n";
				option.insert(new DefaultMutableTreeNode("Option: TCP Alternate Checksum Data"), compteur++);
				ports=scan.next();
				checkOffset();
				sizeoption--;
				res=Integer.parseInt(ports,16);
				s=s+ "taille "+res;
				for(v=0;v<res-2;v++) {
					ports=scan.next();
					checkOffset();
					sizeoption--;
					s=s+ "données "+ports;
			}
				s=s+"\n";
				optionconnu=true;
				
				
			}
			
			if(optionconnu==false) {
			s=s+ "option non pris en compte";
				
			}
		}
		compteurpadding=0;
		while(sizeoption!=0){
			scan.next();
			checkOffset();
			compteurpadding++;
			
		}
		if (compteurpadding!=0){
		s=s+"Nombre octet de padding="+ compteurpadding+"\n";
		option.insert(new DefaultMutableTreeNode("nombre octet de padding="+compteurpadding), compteur++);
			//s=s+"no more option\n";
		}
		racine.add(tcp);
		tcp.add(option);
		
		return s;
		}
	
	
	public  char getCharFromString(String str, int index) { 
        return str.charAt(index); 
    } 
	
	public String HexToString(String hex){

	      StringBuilder sb = new StringBuilder();
	      StringBuilder temp = new StringBuilder();

	      for( int i=0; i<hex.length()-1; i+=2 ){

	          String output = hex.substring(i, (i + 2));
	          int decimal = Integer.parseInt(output, 16);
	          sb.append((char)decimal);

	          temp.append(decimal);
	      }

	      return sb.toString();
	 }
	
	private void checkOffset() {
		offset++;
		if(offset>16) {
			scan.nextLine();
			scan.next();
			offset=1;
		}
	}
	
	private int cptOctets() {
		int nbOctets=0;
		try {
			int off=1;
			while(!scanNbOctets.next().equals("0000")) {
				off++;
				if(off>16) {
					scanNbOctets.nextLine();
					off=1;
				}
				nbOctets++;
			}
			return nbOctets;

		} catch (NoSuchElementException e) {
			System.out.println("Fin comptage octets");
			return nbOctets;
		}
	}
	
	private boolean checkOctets(String s) {
		return s.length()==2;
	}
	
	private boolean checkOffsetFormat(String s) {
		for (int i = 0; i < s.length(); i++) {
			if(s.charAt(0)!='0') {
				return false;
			}
		}
		return true;
	}
	
}	
