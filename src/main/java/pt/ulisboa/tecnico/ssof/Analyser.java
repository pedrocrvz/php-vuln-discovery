package pt.ulisboa.tecnico.ssof;

import java.io.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;

public class Analyser {
    private static final String PATTERNS_PATH = "patterns/all.txt";

    private File sliceFile;
    private List<Vulnerability> vulnerabilities;


    public Analyser(File sliceFile){
        this.sliceFile = sliceFile;
        this.vulnerabilities = new ArrayList<>();
    }

    public void run() throws IOException {
        loadPatterns();
        buildTreeFromJSON();
        findVulnerabilities();
    }

    private void loadPatterns() throws IOException {
        List<String> fileLines = readFile(PATTERNS_PATH);
        for(int i=0; i < fileLines.size(); i=i+5){
            vulnerabilities.add(new Vulnerability(
                    fileLines.get(i), //vuln name
                    Arrays.asList(fileLines.get(i+1).split(",")), //entry points
                    Arrays.asList(fileLines.get(i+2).split(",")), //sanitization functions
                    Arrays.asList(fileLines.get(i+3).split(",")) //sensitive sinks
            ));
        }
    }

    private List<String> readFile(String filePath) throws IOException {
        ArrayList<String> lines = new ArrayList<>();
        BufferedReader br = new BufferedReader(new FileReader(filePath));
        String sCurrentLine;

        while ((sCurrentLine = br.readLine()) != null) {
            lines.add(sCurrentLine);
        }

        br.close();

        return lines;
    }

    private void buildTreeFromJSON(){

    }

    private void findVulnerabilities(){

    }
}
