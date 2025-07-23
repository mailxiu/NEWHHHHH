/*    */
package com.bss.entity;

import com.baomidou.mybatisplus.annotation.TableName;

import java.util.Objects;

/*    */
/*    */
/*    */
@TableName("message_config")
/*    */ public class MessageConfig {
    /*    */   private Integer id;
    /*    */   private String accessKeyId;
    /*    */   private String accessKeySecret;
    /*    */   private String regionId;
    /*    */   private String signName;
    /*    */   private String templateCode;

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.MessageConfig)) return false;
        com.bss.entity.MessageConfig other = (com.bss.entity.MessageConfig) o;
        if (!other.canEqual(this)) return false;
        Object this$id = getId(), other$id = other.getId();
        if (!Objects.equals(this$id, other$id)) return false;
        Object this$accessKeyId = getAccessKeyId(), other$accessKeyId = other.getAccessKeyId();
        if (!Objects.equals(this$accessKeyId, other$accessKeyId))
            return false;
        Object this$accessKeySecret = getAccessKeySecret(), other$accessKeySecret = other.getAccessKeySecret();
        if (!Objects.equals(this$accessKeySecret, other$accessKeySecret))
            return false;
        Object this$regionId = getRegionId(), other$regionId = other.getRegionId();
        if (!Objects.equals(this$regionId, other$regionId)) return false;
        Object this$signName = getSignName(), other$signName = other.getSignName();
        if (!Objects.equals(this$signName, other$signName)) return false;
        Object this$templateCode = getTemplateCode(), other$templateCode = other.getTemplateCode();
        return !(!Objects.equals(this$templateCode, other$templateCode));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.MessageConfig;
    }


    public String toString() {
        return "MessageConfig(id=" + getId() + ", accessKeyId=" + getAccessKeyId() + ", accessKeySecret=" + getAccessKeySecret() + ", regionId=" + getRegionId() + ", signName=" + getSignName() + ", templateCode=" + getTemplateCode() + ")";
    }

    /*    */
    public Integer getId() {
        /* 15 */
        return this.id;
        /*    */
    }

    /*    */
    /* 13 */
    public void setId(Integer id) {
        this.id = id;
    }

    public String getAccessKeyId() {
        /* 17 */
        return this.accessKeyId;
        /*    */
    }

    public void setAccessKeyId(String accessKeyId) {
        this.accessKeyId = accessKeyId;
    }

    public String getAccessKeySecret() {
        /* 19 */
        return this.accessKeySecret;
        /*    */
    }

    public void setAccessKeySecret(String accessKeySecret) {
        this.accessKeySecret = accessKeySecret;
    }

    public String getRegionId() {
        /* 21 */
        return this.regionId;
        /*    */
    }

    public void setRegionId(String regionId) {
        this.regionId = regionId;
    }

    public String getSignName() {
        /* 23 */
        return this.signName;
        /*    */
    }

    public void setSignName(String signName) {
        this.signName = signName;
    }

    public String getTemplateCode() {
        /* 25 */
        return this.templateCode;
        /*    */
    }

    public void setTemplateCode(String templateCode) {
        this.templateCode = templateCode;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\MessageConfig.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */