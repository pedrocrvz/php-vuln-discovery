package pt.ulisboa.tecnico.ssof;

import java.io.File;
import java.io.IOException;

public class App {
    public static void main(String[] args) {
        if(args.length < 1){
            System.err.println("Argument expected");
            System.exit(1);
        }

        String filePath = args[0];
        File file = new File(filePath);

        if(!file.exists() || file.isDirectory()){
            System.err.println("Argument is expected to be a valid file path");
            System.exit(1);
        }

        Analyser analyser = new Analyser(file);

        if(args.length > 1 && args[1].equals("debug"))
            analyser.toggleDebugInfo();

        try {
            analyser.run();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
