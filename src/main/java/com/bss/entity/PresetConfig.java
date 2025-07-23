/*    */
package com.bss.entity;
/*    */
/*    */

import com.baomidou.mybatisplus.annotation.TableName;

import java.util.Objects;

/*    */
/*    */
@TableName("preset_config")
/*    */ public class PresetConfig
        /*    */ {
    /*    */   private Integer id;
    /*    */   private String defaultPortrait;
    /*    */   private String projectPortrait;

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.PresetConfig)) return false;
        com.bss.entity.PresetConfig other = (com.bss.entity.PresetConfig) o;
        if (!other.canEqual(this)) return false;
        Object this$id = getId(), other$id = other.getId();
        if (!Objects.equals(this$id, other$id)) return false;
        Object this$defaultPortrait = getDefaultPortrait(), other$defaultPortrait = other.getDefaultPortrait();
        if (!Objects.equals(this$defaultPortrait, other$defaultPortrait))
            return false;
        Object this$projectPortrait = getProjectPortrait(), other$projectPortrait = other.getProjectPortrait();
        return !(!Objects.equals(this$projectPortrait, other$projectPortrait));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.PresetConfig;
    }



    public String toString() {
        return "PresetConfig(id=" + getId() + ", defaultPortrait=" + getDefaultPortrait() + ", projectPortrait=" + getProjectPortrait() + ")";
    }

    /*    */
    public Integer getId() {
        /* 15 */
        return this.id;
        /*    */
    }

    /*    */
    /*    */
    public void setId(Integer id) {
        /* 13 */
        this.id = id;
    }

    public String getDefaultPortrait() {
        /* 17 */
        return this.defaultPortrait;
        /*    */
    }

    public void setDefaultPortrait(String defaultPortrait) {
        this.defaultPortrait = defaultPortrait;
    }

    public String getProjectPortrait() {
        /* 19 */
        return this.projectPortrait;
        /*    */
    }

    public void setProjectPortrait(String projectPortrait) {
        this.projectPortrait = projectPortrait;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\PresetConfig.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */