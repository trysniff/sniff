pub(super) const REGISTRAR: &str = r#"/*
 * Derived from scip-java v0.13.1's AnalyzerFirExtensionRegistrar.
 * SPDX-License-Identifier: Apache-2.0
 */
package org.scip_code.scip_java.kotlinc

import org.jetbrains.kotlin.fir.extensions.FirExtensionRegistrar
import org.scip_code.scip_java.shared.ScipOptions

class AnalyzerFirExtensionRegistrar(private val options: ScipOptions) : FirExtensionRegistrar() {
    override fun ExtensionRegistrarContext.configurePlugin() {
        +AnalyzerParamsProvider.getFactory(options)
        +::AnalyzerCheckers
        +::SniffAnnotationCheckers
    }
}
"#;

pub(super) const ANNOTATION_CHECKERS: &str = r#"/*
 * Adds compiler-resolved annotation use-site occurrences to scip-java v0.13.1.
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.scip_code.scip_java.kotlinc

import org.jetbrains.kotlin.*
import org.jetbrains.kotlin.com.intellij.lang.LighterASTNode
import org.jetbrains.kotlin.com.intellij.util.diff.FlyweightCapableTreeStructure
import org.jetbrains.kotlin.diagnostics.DiagnosticReporter
import org.jetbrains.kotlin.diagnostics.findChildByType
import org.jetbrains.kotlin.fir.FirSession
import org.jetbrains.kotlin.fir.analysis.checkers.MppCheckerKind
import org.jetbrains.kotlin.fir.analysis.checkers.context.CheckerContext
import org.jetbrains.kotlin.fir.analysis.checkers.expression.ExpressionCheckers
import org.jetbrains.kotlin.fir.analysis.checkers.expression.FirAnnotationCallChecker
import org.jetbrains.kotlin.fir.analysis.checkers.toClassLikeSymbol
import org.jetbrains.kotlin.fir.analysis.extensions.FirAdditionalCheckersExtension
import org.jetbrains.kotlin.fir.expressions.FirAnnotationCall
import org.jetbrains.kotlin.lexer.KtTokens

class SniffAnnotationCheckers(session: FirSession) : FirAdditionalCheckersExtension(session) {
    override val expressionCheckers: ExpressionCheckers
        get() =
            object : ExpressionCheckers() {
                override val annotationCallCheckers: Set<FirAnnotationCallChecker> =
                    setOf(SemanticAnnotationCallChecker())
            }

    private class SemanticAnnotationCallChecker :
        FirAnnotationCallChecker(MppCheckerKind.Common) {
        context(context: CheckerContext, reporter: DiagnosticReporter)
        override fun check(expression: FirAnnotationCall) {
            val source = expression.annotationTypeRef.source ?: return
            val classSymbol = expression.annotationTypeRef.toClassLikeSymbol(context.session) ?: return
            val ktFile = context.containingFile?.sourceFile ?: return
            AnalyzerCheckers.visitors[ktFile]?.visitClassReference(
                classSymbol,
                getIdentifier(source),
                context,
            )
        }
    }

    companion object {
        private fun getIdentifier(element: KtSourceElement): KtSourceElement =
            element.treeStructure
                .findChildByType(element.lighterASTNode, KtTokens.IDENTIFIER)
                ?.toKtLightSourceElement(element.treeStructure) ?: element
    }
}
"#;
