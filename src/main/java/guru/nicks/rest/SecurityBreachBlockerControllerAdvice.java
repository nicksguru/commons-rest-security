package guru.nicks.rest;

import org.springframework.core.annotation.Order;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.InitBinder;

/**
 * Fix for
 * <a href="https://www.rapid7.com/blog/post/2022/03/30/spring4shell-zero-day-vulnerability-in-spring-framework">
 * CVE-2022-22965</a>.
 */
@ControllerAdvice
@Order(10000)
public class SecurityBreachBlockerControllerAdvice {

    @InitBinder
    public void setAllowedFields(WebDataBinder dataBinder) {
        String[] denyList = new String[]{"class.", "Class.", ".class.", ".Class."};
        dataBinder.setDisallowedFields(denyList);
    }

}
