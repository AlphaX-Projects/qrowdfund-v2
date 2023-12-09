package org.qortal.at.qrowdfund.jgiven;

import com.tngtech.jgiven.annotation.Format;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Format( value = QortFormatter.class )
@Retention( RetentionPolicy.RUNTIME )
@Target( { ElementType.PARAMETER, ElementType.ANNOTATION_TYPE } )
public @interface QortAmount {
}
