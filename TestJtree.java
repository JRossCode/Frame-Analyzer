import javax.swing.tree.DefaultTreeCellRenderer;
import javax.swing.*;
import java.awt.*;

public class TestJtree extends JFrame {

  private JPanel jContentPane = null;
  private int num;
  private String tName;
  
  public TestJtree(JTree jt,int num, String tname) {
    super();
    this.tName=tname;
    this.num=num;
    initialize(jt);
    
  }

  private void initialize(JTree jt) {
	 /*--------Modificaiton eventuelle des icônes---------*/
	  DefaultTreeCellRenderer renderer = (DefaultTreeCellRenderer) jt.getCellRenderer();
	  Icon closedIcon = new ImageIcon("closed.png");
	  Icon openIcon = new ImageIcon("open.png");
	  Icon leafIcon = new ImageIcon("leaf.png");
	  renderer.setClosedIcon(closedIcon);
	  renderer.setOpenIcon(openIcon);
	  renderer.setLeafIcon(leafIcon); 
	  /*-------------------------------------------------*/
	
    this.setSize(700, 500);
    this.setLocation(100+(num*30),100+(num*30));

    this.setContentPane(getJContentPane(jt));
    this.setTitle(tName);
    this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

  }

  private JPanel getJContentPane(JTree jt) {
    if (jContentPane == null) {
      jContentPane = new JPanel();
      jContentPane.setLayout(new BorderLayout());
      jContentPane.add(jt, BorderLayout.CENTER);
      jContentPane.add(new JScrollPane(jt, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED));

    }
    return jContentPane;
  }
}