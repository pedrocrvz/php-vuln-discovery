package pt.ulisboa.tecnico.ssof;

import java.io.File;
import java.util.List;

public class Analyser {
    private static final String PATTERNS_FILE_PATH = "patterns/all.txt";

    private File sliceFile;
    private List<String> entryPoints;
    private List<String> sanitazionFunctions;
    private List<String> sensitiveSinks;


    public Analyser(File sliceFile){
        this.sliceFile = sliceFile;
    }

    public void run(){
        loadPatterns();
        buildTreeFromJSON();
        findVulnerabilities();
    }

    private void loadPatterns(){

    }

    private void buildTreeFromJSON(){

    }

    private void findVulnerabilities(){

    }
}
