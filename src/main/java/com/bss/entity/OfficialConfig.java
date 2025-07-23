/*    */
package com.bss.entity;
/*    */
/*    */

import com.baomidou.mybatisplus.annotation.TableName;

import java.io.Serializable;
import java.util.Objects;

/*    */
/*    */
@TableName("official_config")
/*    */ public class OfficialConfig implements Serializable {
    /*    */   private static final long serialVersionUID = 1L;
    /*    */   private Integer id;
    /*    */   private String appId;
    /*    */   private String appSecret;
    /*    */   private String officialName;
    /*    */   private String officialImage;

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.OfficialConfig)) return false;
        com.bss.entity.OfficialConfig other = (com.bss.entity.OfficialConfig) o;
        if (!other.canEqual(this)) return false;
        Object this$id = getId(), other$id = other.getId();
        if (!Objects.equals(this$id, other$id)) return false;
        Object this$appId = getAppId(), other$appId = other.getAppId();
        if (!Objects.equals(this$appId, other$appId)) return false;
        Object this$appSecret = getAppSecret(), other$appSecret = other.getAppSecret();
        if (!Objects.equals(this$appSecret, other$appSecret))
            return false;
        Object this$officialName = getOfficialName(), other$officialName = other.getOfficialName();
        if (!Objects.equals(this$officialName, other$officialName))
            return false;
        Object this$officialImage = getOfficialImage(), other$officialImage = other.getOfficialImage();
        return !(!Objects.equals(this$officialImage, other$officialImage));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.OfficialConfig;
    }


    public String toString() {
        return "OfficialConfig(id=" + getId() + ", appId=" + getAppId() + ", appSecret=" + getAppSecret() + ", officialName=" + getOfficialName() + ", officialImage=" + getOfficialImage() + ")";
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

    public String getAppId() {
        /* 18 */
        return this.appId;
        /*    */
    }

    public void setAppId(String appId) {
        this.appId = appId;
    }

    public String getAppSecret() {
        /* 20 */
        return this.appSecret;
        /*    */
    }

    public void setAppSecret(String appSecret) {
        this.appSecret = appSecret;
    }

    public String getOfficialName() {
        /* 22 */
        return this.officialName;
        /*    */
    }

    public void setOfficialName(String officialName) {
        this.officialName = officialName;
    }

    public String getOfficialImage() {
        /* 24 */
        return this.officialImage;
        /*    */
    }

    public void setOfficialImage(String officialImage) {
        this.officialImage = officialImage;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\OfficialConfig.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */