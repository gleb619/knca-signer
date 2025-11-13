package knca.signer.kalkan;

import lombok.Getter;

import java.util.List;

@Getter
public class KalkanException extends RuntimeException {

    private List<String> availableConstructors;
    private List<String> availableMethods;

    public KalkanException(String message) {
        super(message);
    }

    public KalkanException(String message, Throwable cause) {
        super(message, cause);
    }

    public KalkanException(String message, List<String> availableConstructors, List<String> availableMethods) {
        super(message);
        this.availableConstructors = availableConstructors;
        this.availableMethods = availableMethods;
    }

    public KalkanException(String message, Throwable cause, List<String> availableConstructors, List<String> availableMethods) {
        super(message, cause);
        this.availableConstructors = availableConstructors;
        this.availableMethods = availableMethods;
    }

}
