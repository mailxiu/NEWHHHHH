/*    */
package com.bss.entity;
/*    */
/*    */

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
/*    */ import com.baomidou.mybatisplus.annotation.TableName;
/*    */ import java.io.Serializable;
import java.util.Objects;

/*    */
/*    */
@TableName("system_config")
/*    */ public class SystemConfig implements Serializable {
    private static final long serialVersionUID = 1L;
    /*    */
    @TableId(type = IdType.AUTO)
    /*    */ private Integer id;
    /*    */   private String serviceUrl;
    /*    */   private String galleryUrl;
    private String galleryRoute;
    private String websiteTitle;
    private String menuTitle;

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.SystemConfig)) return false;
        com.bss.entity.SystemConfig other = (com.bss.entity.SystemConfig) o;
        if (!other.canEqual(this)) return false;
        Object this$id = getId(), other$id = other.getId();
        if (!Objects.equals(this$id, other$id)) return false;
        Object this$serviceUrl = getServiceUrl(), other$serviceUrl = other.getServiceUrl();
        if (!Objects.equals(this$serviceUrl, other$serviceUrl))
            return false;
        Object this$galleryUrl = getGalleryUrl(), other$galleryUrl = other.getGalleryUrl();
        if (!Objects.equals(this$galleryUrl, other$galleryUrl))
            return false;
        Object this$galleryRoute = getGalleryRoute(), other$galleryRoute = other.getGalleryRoute();
        if (!Objects.equals(this$galleryRoute, other$galleryRoute))
            return false;
        Object this$websiteTitle = getWebsiteTitle(), other$websiteTitle = other.getWebsiteTitle();
        if (!Objects.equals(this$websiteTitle, other$websiteTitle))
            return false;
        Object this$menuTitle = getMenuTitle(), other$menuTitle = other.getMenuTitle();
        return !(!Objects.equals(this$menuTitle, other$menuTitle));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.SystemConfig;
    }


    public String toString() {
        return "SystemConfig(id=" + getId() + ", serviceUrl=" + getServiceUrl() + ", galleryUrl=" + getGalleryUrl() + ", galleryRoute=" + getGalleryRoute() + ", websiteTitle=" + getWebsiteTitle() + ", menuTitle=" + getMenuTitle() + ")";
    }

    /*    */
    /*    */
    /*    */
    /*    */
    public Integer getId() {
        /* 19 */
        return this.id;
        /*    */
    }

    /*    */
    /* 14 */
    public void setId(Integer id) {
        this.id = id;
    }

    public String getServiceUrl() {
        /* 21 */
        return this.serviceUrl;
        /*    */
    }

    public void setServiceUrl(String serviceUrl) {
        this.serviceUrl = serviceUrl;
    }

    public String getGalleryUrl() {
        /* 23 */
        return this.galleryUrl;
        /*    */
    }

    public void setGalleryUrl(String galleryUrl) {
        this.galleryUrl = galleryUrl;
    }

    public String getGalleryRoute() {
        /* 25 */
        return this.galleryRoute;
        /*    */
    }

    public void setGalleryRoute(String galleryRoute) {
        this.galleryRoute = galleryRoute;
    }

    public String getWebsiteTitle() {
        /* 27 */
        return this.websiteTitle;
        /*    */
    }

    public void setWebsiteTitle(String websiteTitle) {
        this.websiteTitle = websiteTitle;
    }

    public String getMenuTitle() {
        /* 29 */
        return this.menuTitle;
        /*    */
    }

    public void setMenuTitle(String menuTitle) {
        this.menuTitle = menuTitle;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\SystemConfig.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */