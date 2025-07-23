/*    */
package com.bss.entity;
/*    */
/*    */

import com.baomidou.mybatisplus.annotation.TableName;

import java.io.Serializable;
import java.util.Objects;

/*    */
/*    */
@TableName("pay_alipay_config")
/*    */ public class PayAlipayConfig implements Serializable {
    /*    */   private static final long serialVersionUID = 1L;
    /*    */   private Integer id;
    /*    */   private String appid;
    /*    */   private String privateKey;
    /*    */   private String alipayPublicKey;

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.PayAlipayConfig)) return false;
        com.bss.entity.PayAlipayConfig other = (com.bss.entity.PayAlipayConfig) o;
        if (!other.canEqual(this)) return false;
        Object this$id = getId(), other$id = other.getId();
        if (!Objects.equals(this$id, other$id)) return false;
        Object this$appid = getAppid(), other$appid = other.getAppid();
        if (!Objects.equals(this$appid, other$appid)) return false;
        Object this$privateKey = getPrivateKey(), other$privateKey = other.getPrivateKey();
        if (!Objects.equals(this$privateKey, other$privateKey))
            return false;
        Object this$alipayPublicKey = getAlipayPublicKey(), other$alipayPublicKey = other.getAlipayPublicKey();
        return !(!Objects.equals(this$alipayPublicKey, other$alipayPublicKey));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.PayAlipayConfig;
    }


    public String toString() {
        return "PayAlipayConfig(id=" + getId() + ", appid=" + getAppid() + ", privateKey=" + getPrivateKey() + ", alipayPublicKey=" + getAlipayPublicKey() + ")";
    }

    /*    */
    public Integer getId() {
        /* 16 */
        return this.id;
        /*    */
    }

    /*    */
    /* 14 */
    public void setId(Integer id) {
        this.id = id;
    }

    public String getAppid() {
        /* 18 */
        return this.appid;
        /*    */
    }

    public void setAppid(String appid) {
        this.appid = appid;
    }

    public String getPrivateKey() {
        /* 20 */
        return this.privateKey;
        /*    */
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }

    public String getAlipayPublicKey() {
        /* 22 */
        return this.alipayPublicKey;
        /*    */
    }

    public void setAlipayPublicKey(String alipayPublicKey) {
        this.alipayPublicKey = alipayPublicKey;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\PayAlipayConfig.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */