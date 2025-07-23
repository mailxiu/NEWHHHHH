/*    */
package com.bss.entity;
/*    */
/*    */

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
/*    */ import com.baomidou.mybatisplus.annotation.TableName;
/*    */ import java.io.Serializable;
/*    */ import java.util.Date;
import java.util.Objects;

/*    */
/*    */
@TableName("applet_config")
/*    */ public class AppletConfig implements Serializable {
    private static final long serialVersionUID = 1L;
    /*    */
    @TableId(type = IdType.AUTO)
    /*    */ private Integer id;
    /*    */   private String appId;
    /*    */   private String secret;
    private String accessToken;
    private Date updateTime;

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.AppletConfig)) return false;
        com.bss.entity.AppletConfig other = (com.bss.entity.AppletConfig) o;
        if (!other.canEqual(this)) return false;
        Object this$id = getId(), other$id = other.getId();
        if (!Objects.equals(this$id, other$id)) return false;
        Object this$appId = getAppId(), other$appId = other.getAppId();
        if (!Objects.equals(this$appId, other$appId)) return false;
        Object this$secret = getSecret(), other$secret = other.getSecret();
        if (!Objects.equals(this$secret, other$secret)) return false;
        Object this$accessToken = getAccessToken(), other$accessToken = other.getAccessToken();
        if (!Objects.equals(this$accessToken, other$accessToken))
            return false;
        Object this$updateTime = getUpdateTime(), other$updateTime = other.getUpdateTime();
        return !(!Objects.equals(this$updateTime, other$updateTime));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.AppletConfig;
    }


    public String toString() {
        return "AppletConfig(id=" + getId() + ", appId=" + getAppId() + ", secret=" + getSecret() + ", accessToken=" + getAccessToken() + ", updateTime=" + getUpdateTime() + ")";
    }

    /*    */
    /*    */
    public Integer getId() {
        /* 18 */
        return this.id;
        /*    */
    }

    /*    */
    /* 15 */
    public void setId(Integer id) {
        this.id = id;
    }

    public String getAppId() {
        /* 20 */
        return this.appId;
        /*    */
    }

    public void setAppId(String appId) {
        this.appId = appId;
    }

    public String getSecret() {
        /* 22 */
        return this.secret;
        /*    */
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public String getAccessToken() {
        /* 24 */
        return this.accessToken;
        /*    */
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public Date getUpdateTime() {
        /* 26 */
        return this.updateTime;
        /*    */
    }

    public void setUpdateTime(Date updateTime) {
        this.updateTime = updateTime;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\AppletConfig.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */