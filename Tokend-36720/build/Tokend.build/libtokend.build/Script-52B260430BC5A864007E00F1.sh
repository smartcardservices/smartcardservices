#!/bin/sh
for variant in ${BUILD_VARIANTS}
do
	postfix=`echo _${variant} | sed 's/_normal//'`
	frmwk="${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework"
	versa="${frmwk}/Versions/A"
	cp "${BUILT_PRODUCTS_DIR}/lib${PRODUCT_NAME}${postfix}.a" "${versa}/${PRODUCT_NAME}${postfix}"
	ln -fs "${versa}/${PRODUCT_NAME}${postfix}" ${frmwk}/${PRODUCT_NAME}${postfix}
	nmedit -p "${versa}/${PRODUCT_NAME}${postfix}"
	ranlib    "${versa}/${PRODUCT_NAME}${postfix}"
done
