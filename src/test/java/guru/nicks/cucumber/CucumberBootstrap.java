package guru.nicks.cucumber;

import guru.nicks.cucumber.world.TextWorld;

import io.cucumber.spring.CucumberContextConfiguration;
import org.springframework.test.context.ContextConfiguration;

/**
 * Initializes Spring Context shared by all scenarios. Mocking is done inside step definition classes to let each
 * scenario program a different behavior. However, purely default mocks can be declared here (using annotations), but
 * remember to not alter their behavior in step classes.
 */
@CucumberContextConfiguration
@ContextConfiguration(classes = {
        // scenario-scoped states
        TextWorld.class
})
//@Import(AnnotationAwareAspectJAutoProxyCreator.class) // activate aspects
public class CucumberBootstrap {
}
