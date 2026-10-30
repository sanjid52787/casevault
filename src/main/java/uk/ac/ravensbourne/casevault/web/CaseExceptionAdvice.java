package uk.ac.ravensbourne.casevault.web;
import jakarta.persistence.OptimisticLockException; import org.springframework.stereotype.Controller; import org.springframework.web.bind.annotation.*;
/** Avoids exposing persistence details when concurrent case edits conflict. */
@ControllerAdvice public class CaseExceptionAdvice { @ExceptionHandler(OptimisticLockException.class) String conflict(){return "case-conflict";} }
