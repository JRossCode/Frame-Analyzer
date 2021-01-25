import java.util.List;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.dnd.DnDConstants;
import java.awt.dnd.DropTargetDragEvent;
import java.awt.dnd.DropTargetDropEvent;
import java.awt.dnd.DropTargetEvent;
import java.awt.dnd.DropTargetListener;
import java.io.File;

public class MyDragDropListener implements DropTargetListener {
	String path="";
	String name="";
    public void drop(DropTargetDropEvent event) {
        
    	event.acceptDrop(DnDConstants.ACTION_COPY);
        Transferable transferable = event.getTransferable();
        DataFlavor[] flavors = transferable.getTransferDataFlavors();
       
        for (DataFlavor flavor : flavors) {
            try {
                if (flavor.isFlavorJavaFileListType()) {
 
					List<File> files =(List) transferable.getTransferData(flavor);

					name = files.get(0).getName();
					path=files.get(0).getPath();
					 System.out.println("File path is '" + files.get(0).getPath() + "'.");
                }

            } catch (Exception e) {

                e.printStackTrace();

            }
        }

        event.dropComplete(true);

    }
    
    public String getPath() {
    	return path;
    }
    
    public String getName() {
    	return name;
    }

    @Override
    public void dragEnter(DropTargetDragEvent event) {
    }

    @Override
    public void dragExit(DropTargetEvent event) {
    }

    @Override
    public void dragOver(DropTargetDragEvent event) {
    }

    public void dropActionChanged(DropTargetDragEvent event) {
    }

}