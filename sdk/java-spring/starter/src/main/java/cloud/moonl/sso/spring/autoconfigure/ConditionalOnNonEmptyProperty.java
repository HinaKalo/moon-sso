package cloud.moonl.sso.spring.autoconfigure;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.Map;

import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.boot.autoconfigure.condition.SpringBootCondition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.Conditional;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.util.StringUtils;

/**
 * Matches when a property is set to a non-blank value ({@code ${ENV:}} placeholders that
 * resolve to an empty string do not match, unlike {@code @ConditionalOnProperty}).
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ ElementType.TYPE, ElementType.METHOD })
@Documented
@Conditional(ConditionalOnNonEmptyProperty.OnNonEmptyPropertyCondition.class)
@interface ConditionalOnNonEmptyProperty {

	/** Full property name. */
	String value();

	/** Condition implementation. */
	final class OnNonEmptyPropertyCondition extends SpringBootCondition {

		@Override
		public ConditionOutcome getMatchOutcome(ConditionContext context, AnnotatedTypeMetadata metadata) {
			Map<String, Object> attributes = metadata.getAnnotationAttributes(ConditionalOnNonEmptyProperty.class.getName());
			String name = (attributes != null) ? (String) attributes.get("value") : null;
			if (name == null) {
				return ConditionOutcome.noMatch("no property name");
			}
			String value = context.getEnvironment().getProperty(name);
			return StringUtils.hasText(value) ? ConditionOutcome.match(name + " is set")
					: ConditionOutcome.noMatch(name + " is empty or missing");
		}

	}

}
