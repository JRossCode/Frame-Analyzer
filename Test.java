import java.awt.BorderLayout;
import java.awt.dnd.DropTarget;
import java.io.File;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.SwingConstants;


public class Test {
	
	public static void main(String[] args) {
		
		try {
			
			/*---------Drag and drop----------*/
			JFrame frame= new JFrame("Analyseur");
			frame.setSize(250, 150);
	        JLabel myLabel = new JLabel("Déposer le fichier txt a analyser", SwingConstants.CENTER);
	        MyDragDropListener myDragDropListener = new MyDragDropListener();
	        new DropTarget(myLabel,myDragDropListener);
	        frame.getContentPane().add(BorderLayout.CENTER, myLabel);
	        frame.setVisible(true);
	        
	        while (myDragDropListener.getPath()=="") {
	        	Thread.sleep(10);
	        }
	        
	        frame.setVisible(false);
	        File f = new File(myDragDropListener.getPath());
	        /*-------------------------------*/
	        
	        //Création du fichier contenant l'analyse 
			File fr = new File(myDragDropListener.getPath().replaceAll(myDragDropListener.getName(), "res")); 
			fr.createNewFile();
			
			/*---------Analyse----------*/
			Analyseur a= new Analyseur(f);
			a.analyse(fr);

			
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		
	}

	
}

