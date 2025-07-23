/*    */
package com.bss.entity;
/*    */
/*    */

import com.baomidou.mybatisplus.annotation.TableName;
/*    */ import java.io.Serializable;
import java.util.Objects;

/*    */
/*    */
@TableName("payment_config")
/*    */ public class PaymentConfig implements Serializable {
    private static final long serialVersionUID = 1L;
    /*    */   private Integer id;
    /*    */   private String merchantId;
    /*    */   private String merchantSerialNumber;
    /*    */   private String apiV3Key;
    private String privateKeyFromPath;
    private String publicKeyFromPath;
    private String publicKeyId;

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.PaymentConfig)) return false;
        com.bss.entity.PaymentConfig other = (com.bss.entity.PaymentConfig) o;
        if (!other.canEqual(this)) return false;
        Object this$id = getId(), other$id = other.getId();
        if (!Objects.equals(this$id, other$id)) return false;
        Object this$merchantId = getMerchantId(), other$merchantId = other.getMerchantId();
        if (!Objects.equals(this$merchantId, other$merchantId))
            return false;
        Object this$merchantSerialNumber = getMerchantSerialNumber(), other$merchantSerialNumber = other.getMerchantSerialNumber();
        if (!Objects.equals(this$merchantSerialNumber, other$merchantSerialNumber))
            return false;
        Object this$apiV3Key = getApiV3Key(), other$apiV3Key = other.getApiV3Key();
        if (!Objects.equals(this$apiV3Key, other$apiV3Key)) return false;
        Object this$privateKeyFromPath = getPrivateKeyFromPath(), other$privateKeyFromPath = other.getPrivateKeyFromPath();
        if (!Objects.equals(this$privateKeyFromPath, other$privateKeyFromPath))
            return false;
        Object this$publicKeyFromPath = getPublicKeyFromPath(), other$publicKeyFromPath = other.getPublicKeyFromPath();
        if (!Objects.equals(this$publicKeyFromPath, other$publicKeyFromPath))
            return false;
        Object this$publicKeyId = getPublicKeyId(), other$publicKeyId = other.getPublicKeyId();
        return !(!Objects.equals(this$publicKeyId, other$publicKeyId));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.PaymentConfig;
    }


    public String toString() {
        return "PaymentConfig(id=" + getId() + ", merchantId=" + getMerchantId() + ", merchantSerialNumber=" + getMerchantSerialNumber() + ", apiV3Key=" + getApiV3Key() + ", privateKeyFromPath=" + getPrivateKeyFromPath() + ", publicKeyFromPath=" + getPublicKeyFromPath() + ", publicKeyId=" + getPublicKeyId() + ")";
    }

    /*    */
    public Integer getId() {
        /* 16 */
        return this.id;
        /*    */
    }

    /*    */
    /*    */
    public void setId(Integer id) {
        /* 14 */
        this.id = id;
    }

    public String getMerchantId() {
        /* 18 */
        return this.merchantId;
        /*    */
    }

    public void setMerchantId(String merchantId) {
        this.merchantId = merchantId;
    }

    public String getMerchantSerialNumber() {
        /* 20 */
        return this.merchantSerialNumber;
        /*    */
    }

    public void setMerchantSerialNumber(String merchantSerialNumber) {
        this.merchantSerialNumber = merchantSerialNumber;
    }

    public String getApiV3Key() {
        /* 22 */
        return this.apiV3Key;
        /*    */
    }

    public void setApiV3Key(String apiV3Key) {
        this.apiV3Key = apiV3Key;
    }

    public String getPrivateKeyFromPath() {
        /* 24 */
        return this.privateKeyFromPath;
        /*    */
    }

    public void setPrivateKeyFromPath(String privateKeyFromPath) {
        this.privateKeyFromPath = privateKeyFromPath;
    }

    public String getPublicKeyFromPath() {
        /* 26 */
        return this.publicKeyFromPath;
        /*    */
    }

    public void setPublicKeyFromPath(String publicKeyFromPath) {
        this.publicKeyFromPath = publicKeyFromPath;
    }

    public String getPublicKeyId() {
        /* 28 */
        return this.publicKeyId;
        /*    */
    }

    public void setPublicKeyId(String publicKeyId) {
        this.publicKeyId = publicKeyId;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\PaymentConfig.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */