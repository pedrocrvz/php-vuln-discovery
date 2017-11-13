package pt.ulisboa.tecnico.ssof;

public enum NodeType {
    ASSIGN,
    CONCAT,
    FUNCALL,
    ECHO,
    PROGRAM,
    STRING,
    VARIABLE,
    ENCAPSED, INLINE, UNKNOWN, IF, COMPARISON, WHILE, NUMBER, BLOCK
}
