/*    */
package com.bss.entity;

import com.baomidou.mybatisplus.annotation.TableName;

/*    */
/*    */
@TableName("wechat_app_pay_config")
/*    */ public class WechatAppPayConfig {
    /*    */   private Integer id;
    /*    */   private String merchantId;
    /*    */   private String merchantSerialNumber;
    /*    */   private String apiV3Key;
    /*    */   private String privateKeyFromPath;
    /*    */   private String publicKeyFromPath;
    /*    */   private String publicKeyId;

    /*    */
    /* 13 */
    public void setId(Integer id) {
        this.id = id;
    }

    public void setMerchantId(String merchantId) {
        this.merchantId = merchantId;
    }

    public void setMerchantSerialNumber(String merchantSerialNumber) {
        this.merchantSerialNumber = merchantSerialNumber;
    }

    public void setApiV3Key(String apiV3Key) {
        this.apiV3Key = apiV3Key;
    }

    public void setPrivateKeyFromPath(String privateKeyFromPath) {
        this.privateKeyFromPath = privateKeyFromPath;
    }

    public void setPublicKeyFromPath(String publicKeyFromPath) {
        this.publicKeyFromPath = publicKeyFromPath;
    }

    public void setPublicKeyId(String publicKeyId) {
        this.publicKeyId = publicKeyId;
    }

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.WechatAppPayConfig)) return false;
        com.bss.entity.WechatAppPayConfig other = (com.bss.entity.WechatAppPayConfig) o;
        if (!other.canEqual(this)) return false;
        Object this$id = getId(), other$id = other.getId();
        if ((this$id == null) ? (other$id != null) : !this$id.equals(other$id)) return false;
        Object this$merchantId = getMerchantId(), other$merchantId = other.getMerchantId();
        if ((this$merchantId == null) ? (other$merchantId != null) : !this$merchantId.equals(other$merchantId))
            return false;
        Object this$merchantSerialNumber = getMerchantSerialNumber(), other$merchantSerialNumber = other.getMerchantSerialNumber();
        if ((this$merchantSerialNumber == null) ? (other$merchantSerialNumber != null) : !this$merchantSerialNumber.equals(other$merchantSerialNumber))
            return false;
        Object this$apiV3Key = getApiV3Key(), other$apiV3Key = other.getApiV3Key();
        if ((this$apiV3Key == null) ? (other$apiV3Key != null) : !this$apiV3Key.equals(other$apiV3Key)) return false;
        Object this$privateKeyFromPath = getPrivateKeyFromPath(), other$privateKeyFromPath = other.getPrivateKeyFromPath();
        if ((this$privateKeyFromPath == null) ? (other$privateKeyFromPath != null) : !this$privateKeyFromPath.equals(other$privateKeyFromPath))
            return false;
        Object this$publicKeyFromPath = getPublicKeyFromPath(), other$publicKeyFromPath = other.getPublicKeyFromPath();
        if ((this$publicKeyFromPath == null) ? (other$publicKeyFromPath != null) : !this$publicKeyFromPath.equals(other$publicKeyFromPath))
            return false;
        Object this$publicKeyId = getPublicKeyId(), other$publicKeyId = other.getPublicKeyId();
        return !((this$publicKeyId == null) ? (other$publicKeyId != null) : !this$publicKeyId.equals(other$publicKeyId));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.WechatAppPayConfig;
    }


    public String toString() {
        return "WechatAppPayConfig(id=" + getId() + ", merchantId=" + getMerchantId() + ", merchantSerialNumber=" + getMerchantSerialNumber() + ", apiV3Key=" + getApiV3Key() + ", privateKeyFromPath=" + getPrivateKeyFromPath() + ", publicKeyFromPath=" + getPublicKeyFromPath() + ", publicKeyId=" + getPublicKeyId() + ")";
    }

    /*    */
    public Integer getId() {
        /* 15 */
        return this.id;
        /*    */
    }

    public String getMerchantId() {
        /* 17 */
        return this.merchantId;
        /*    */
    }

    public String getMerchantSerialNumber() {
        /* 19 */
        return this.merchantSerialNumber;
        /*    */
    }

    public String getApiV3Key() {
        /* 21 */
        return this.apiV3Key;
        /*    */
    }

    public String getPrivateKeyFromPath() {
        /* 23 */
        return this.privateKeyFromPath;
        /*    */
    }

    public String getPublicKeyFromPath() {
        /* 25 */
        return this.publicKeyFromPath;
        /*    */
    }

    public String getPublicKeyId() {
        /* 27 */
        return this.publicKeyId;
        /*    */
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\WechatAppPayConfig.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */