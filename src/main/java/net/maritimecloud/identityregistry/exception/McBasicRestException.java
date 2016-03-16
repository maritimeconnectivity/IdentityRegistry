package net.maritimecloud.identityregistry.exception;

import java.util.Date;

import org.springframework.http.HttpStatus;

public class McBasicRestException extends Exception {

    // mimics the standard spring error structure on exceptions 
    protected HttpStatus status;
    protected String error;
    protected String errorMessage;
    protected String path;
    protected long timestamp;
    
    public McBasicRestException(HttpStatus status, String errorMessage, String path) {
        this.status = status;
        this.errorMessage = errorMessage;
        this.path = path;
        this.timestamp = new Date().getTime();
        this.error = status.getReasonPhrase();
    }

    public HttpStatus getStatus() {
        return status;
    }

    public void setStatus(HttpStatus status) {
        this.status = status;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }
}
