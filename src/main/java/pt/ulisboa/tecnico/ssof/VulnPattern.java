package pt.ulisboa.tecnico.ssof;

import java.util.List;

public class VulnPattern {
    private String name;
    private List<String> entryPoints;
    private List<String> sanitizeFunctions;
    private List<String> sensitiveSinks;

    public VulnPattern(String name, List<String> entryPoints, List<String> sanitizeFunctions, List<String> sensitiveSinks) {
        this.name = name;
        this.entryPoints = entryPoints;
        this.sanitizeFunctions = sanitizeFunctions;
        this.sensitiveSinks = sensitiveSinks;
    }

    public List<String> getSensitiveSinks() {
        return sensitiveSinks;
    }

    public String getName() {
        return name;
    }

    @Override
    public String toString(){
        return "[VULN] name="+name+", entryPoints="+entryPoints+", sanitizeFunctions="+sanitizeFunctions+", " +
                "sensitiveSinks="+sensitiveSinks+"";
    }
}
